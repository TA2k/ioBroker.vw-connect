.class public final La71/b0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Landroidx/lifecycle/b1;Ll2/b1;Ll2/b1;Ll2/b1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p7, p0, La71/b0;->d:I

    iput-object p1, p0, La71/b0;->f:Ljava/lang/Object;

    iput-object p2, p0, La71/b0;->g:Ljava/lang/Object;

    iput-object p3, p0, La71/b0;->e:Ljava/lang/Object;

    iput-object p4, p0, La71/b0;->h:Ljava/lang/Object;

    iput-object p5, p0, La71/b0;->i:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 2
    iput p6, p0, La71/b0;->d:I

    iput-object p1, p0, La71/b0;->g:Ljava/lang/Object;

    iput-object p2, p0, La71/b0;->h:Ljava/lang/Object;

    iput-object p3, p0, La71/b0;->i:Ljava/lang/Object;

    iput-object p4, p0, La71/b0;->e:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ll2/b1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 3
    iput p7, p0, La71/b0;->d:I

    iput-object p1, p0, La71/b0;->f:Ljava/lang/Object;

    iput-object p2, p0, La71/b0;->g:Ljava/lang/Object;

    iput-object p3, p0, La71/b0;->h:Ljava/lang/Object;

    iput-object p4, p0, La71/b0;->i:Ljava/lang/Object;

    iput-object p5, p0, La71/b0;->e:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 10

    .line 1
    iget v0, p0, La71/b0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, La71/b0;

    .line 7
    .line 8
    iget-object v0, p0, La71/b0;->g:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, v0

    .line 11
    check-cast v2, Lvy/v;

    .line 12
    .line 13
    iget-object v0, p0, La71/b0;->h:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v3, v0

    .line 16
    check-cast v3, Lne0/s;

    .line 17
    .line 18
    iget-object v0, p0, La71/b0;->i:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v4, v0

    .line 21
    check-cast v4, Lcn0/c;

    .line 22
    .line 23
    iget-object p0, p0, La71/b0;->e:Ljava/lang/Object;

    .line 24
    .line 25
    move-object v5, p0

    .line 26
    check-cast v5, Lcn0/c;

    .line 27
    .line 28
    const/4 v7, 0x5

    .line 29
    move-object v6, p2

    .line 30
    invoke-direct/range {v1 .. v7}, La71/b0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    iput-object p1, v1, La71/b0;->f:Ljava/lang/Object;

    .line 34
    .line 35
    return-object v1

    .line 36
    :pswitch_0
    move-object v8, p2

    .line 37
    new-instance v2, La71/b0;

    .line 38
    .line 39
    iget-object p2, p0, La71/b0;->g:Ljava/lang/Object;

    .line 40
    .line 41
    move-object v3, p2

    .line 42
    check-cast v3, Lq1/e;

    .line 43
    .line 44
    iget-object p2, p0, La71/b0;->h:Ljava/lang/Object;

    .line 45
    .line 46
    move-object v4, p2

    .line 47
    check-cast v4, Lv3/f1;

    .line 48
    .line 49
    iget-object p2, p0, La71/b0;->i:Ljava/lang/Object;

    .line 50
    .line 51
    move-object v5, p2

    .line 52
    check-cast v5, La4/b;

    .line 53
    .line 54
    iget-object p0, p0, La71/b0;->e:Ljava/lang/Object;

    .line 55
    .line 56
    move-object v6, p0

    .line 57
    check-cast v6, Lc41/b;

    .line 58
    .line 59
    move-object v7, v8

    .line 60
    const/4 v8, 0x4

    .line 61
    invoke-direct/range {v2 .. v8}, La71/b0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 62
    .line 63
    .line 64
    iput-object p1, v2, La71/b0;->f:Ljava/lang/Object;

    .line 65
    .line 66
    return-object v2

    .line 67
    :pswitch_1
    move-object v8, p2

    .line 68
    new-instance v2, La71/b0;

    .line 69
    .line 70
    iget-object p1, p0, La71/b0;->f:Ljava/lang/Object;

    .line 71
    .line 72
    move-object v3, p1

    .line 73
    check-cast v3, Ljava/lang/Long;

    .line 74
    .line 75
    iget-object p1, p0, La71/b0;->g:Ljava/lang/Object;

    .line 76
    .line 77
    move-object v4, p1

    .line 78
    check-cast v4, Li2/z;

    .line 79
    .line 80
    iget-object p1, p0, La71/b0;->h:Ljava/lang/Object;

    .line 81
    .line 82
    move-object v5, p1

    .line 83
    check-cast v5, Li2/e0;

    .line 84
    .line 85
    iget-object p1, p0, La71/b0;->i:Ljava/lang/Object;

    .line 86
    .line 87
    move-object v6, p1

    .line 88
    check-cast v6, Ljava/util/Locale;

    .line 89
    .line 90
    iget-object p0, p0, La71/b0;->e:Ljava/lang/Object;

    .line 91
    .line 92
    move-object v7, p0

    .line 93
    check-cast v7, Ll2/b1;

    .line 94
    .line 95
    const/4 v9, 0x3

    .line 96
    invoke-direct/range {v2 .. v9}, La71/b0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 97
    .line 98
    .line 99
    return-object v2

    .line 100
    :pswitch_2
    move-object v8, p2

    .line 101
    new-instance v2, La71/b0;

    .line 102
    .line 103
    iget-object p1, p0, La71/b0;->f:Ljava/lang/Object;

    .line 104
    .line 105
    move-object v3, p1

    .line 106
    check-cast v3, Lce/j;

    .line 107
    .line 108
    iget-object p1, p0, La71/b0;->g:Ljava/lang/Object;

    .line 109
    .line 110
    move-object v4, p1

    .line 111
    check-cast v4, Lce/u;

    .line 112
    .line 113
    iget-object p1, p0, La71/b0;->e:Ljava/lang/Object;

    .line 114
    .line 115
    move-object v5, p1

    .line 116
    check-cast v5, Ll2/b1;

    .line 117
    .line 118
    iget-object p1, p0, La71/b0;->h:Ljava/lang/Object;

    .line 119
    .line 120
    move-object v6, p1

    .line 121
    check-cast v6, Ll2/b1;

    .line 122
    .line 123
    iget-object p0, p0, La71/b0;->i:Ljava/lang/Object;

    .line 124
    .line 125
    move-object v7, p0

    .line 126
    check-cast v7, Ll2/b1;

    .line 127
    .line 128
    const/4 v9, 0x2

    .line 129
    invoke-direct/range {v2 .. v9}, La71/b0;-><init>(Ljava/lang/Object;Landroidx/lifecycle/b1;Ll2/b1;Ll2/b1;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 130
    .line 131
    .line 132
    return-object v2

    .line 133
    :pswitch_3
    move-object v8, p2

    .line 134
    new-instance v2, La71/b0;

    .line 135
    .line 136
    iget-object p1, p0, La71/b0;->f:Ljava/lang/Object;

    .line 137
    .line 138
    move-object v3, p1

    .line 139
    check-cast v3, Lag/k;

    .line 140
    .line 141
    iget-object p1, p0, La71/b0;->g:Ljava/lang/Object;

    .line 142
    .line 143
    move-object v4, p1

    .line 144
    check-cast v4, Lag/u;

    .line 145
    .line 146
    iget-object p1, p0, La71/b0;->e:Ljava/lang/Object;

    .line 147
    .line 148
    move-object v5, p1

    .line 149
    check-cast v5, Ll2/b1;

    .line 150
    .line 151
    iget-object p1, p0, La71/b0;->h:Ljava/lang/Object;

    .line 152
    .line 153
    move-object v6, p1

    .line 154
    check-cast v6, Ll2/b1;

    .line 155
    .line 156
    iget-object p0, p0, La71/b0;->i:Ljava/lang/Object;

    .line 157
    .line 158
    move-object v7, p0

    .line 159
    check-cast v7, Ll2/b1;

    .line 160
    .line 161
    const/4 v9, 0x1

    .line 162
    invoke-direct/range {v2 .. v9}, La71/b0;-><init>(Ljava/lang/Object;Landroidx/lifecycle/b1;Ll2/b1;Ll2/b1;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 163
    .line 164
    .line 165
    return-object v2

    .line 166
    :pswitch_4
    move-object v8, p2

    .line 167
    new-instance v2, La71/b0;

    .line 168
    .line 169
    iget-object p1, p0, La71/b0;->f:Ljava/lang/Object;

    .line 170
    .line 171
    move-object v3, p1

    .line 172
    check-cast v3, Ld71/c;

    .line 173
    .line 174
    iget-object p1, p0, La71/b0;->g:Ljava/lang/Object;

    .line 175
    .line 176
    move-object v4, p1

    .line 177
    check-cast v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 178
    .line 179
    iget-object p1, p0, La71/b0;->h:Ljava/lang/Object;

    .line 180
    .line 181
    move-object v5, p1

    .line 182
    check-cast v5, Lh71/p;

    .line 183
    .line 184
    iget-object p1, p0, La71/b0;->i:Ljava/lang/Object;

    .line 185
    .line 186
    move-object v6, p1

    .line 187
    check-cast v6, Lh70/o;

    .line 188
    .line 189
    iget-object p0, p0, La71/b0;->e:Ljava/lang/Object;

    .line 190
    .line 191
    move-object v7, p0

    .line 192
    check-cast v7, Ll2/b1;

    .line 193
    .line 194
    const/4 v9, 0x0

    .line 195
    invoke-direct/range {v2 .. v9}, La71/b0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 196
    .line 197
    .line 198
    return-object v2

    .line 199
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, La71/b0;->d:I

    .line 2
    .line 3
    check-cast p1, Lvy0/b0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, La71/b0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, La71/b0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, La71/b0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    invoke-virtual {p0, p1, p2}, La71/b0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, La71/b0;

    .line 27
    .line 28
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-virtual {p0, p1}, La71/b0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :pswitch_1
    invoke-virtual {p0, p1, p2}, La71/b0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    check-cast p0, La71/b0;

    .line 40
    .line 41
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    invoke-virtual {p0, p1}, La71/b0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    return-object p1

    .line 47
    :pswitch_2
    invoke-virtual {p0, p1, p2}, La71/b0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    check-cast p0, La71/b0;

    .line 52
    .line 53
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    invoke-virtual {p0, p1}, La71/b0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    return-object p1

    .line 59
    :pswitch_3
    invoke-virtual {p0, p1, p2}, La71/b0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    check-cast p0, La71/b0;

    .line 64
    .line 65
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    invoke-virtual {p0, p1}, La71/b0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    return-object p1

    .line 71
    :pswitch_4
    invoke-virtual {p0, p1, p2}, La71/b0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    check-cast p0, La71/b0;

    .line 76
    .line 77
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 78
    .line 79
    invoke-virtual {p0, p1}, La71/b0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    return-object p1

    .line 83
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, La71/b0;->d:I

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    const/4 v3, 0x0

    .line 7
    iget-object v4, p0, La71/b0;->e:Ljava/lang/Object;

    .line 8
    .line 9
    iget-object v5, p0, La71/b0;->i:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object v6, p0, La71/b0;->h:Ljava/lang/Object;

    .line 12
    .line 13
    iget-object v7, p0, La71/b0;->g:Ljava/lang/Object;

    .line 14
    .line 15
    packed-switch v0, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, La71/b0;->f:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lvy0/b0;

    .line 21
    .line 22
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 23
    .line 24
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    check-cast v7, Lvy/v;

    .line 28
    .line 29
    check-cast v6, Lne0/s;

    .line 30
    .line 31
    check-cast v5, Lcn0/c;

    .line 32
    .line 33
    invoke-static {v7, p0, v6, v5}, Lvy/v;->h(Lvy/v;Lvy0/b0;Lne0/s;Lcn0/c;)V

    .line 34
    .line 35
    .line 36
    const/16 p0, 0x17

    .line 37
    .line 38
    if-eqz v5, :cond_0

    .line 39
    .line 40
    invoke-static {v7}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    new-instance v0, Ltr0/e;

    .line 45
    .line 46
    invoke-direct {v0, p0, v5, v7, v3}, Ltr0/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 47
    .line 48
    .line 49
    invoke-static {p1, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 50
    .line 51
    .line 52
    :cond_0
    check-cast v4, Lcn0/c;

    .line 53
    .line 54
    if-eqz v4, :cond_1

    .line 55
    .line 56
    invoke-static {v7}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    new-instance v0, Ltr0/e;

    .line 61
    .line 62
    invoke-direct {v0, p0, v4, v7, v3}, Ltr0/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 63
    .line 64
    .line 65
    invoke-static {p1, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 66
    .line 67
    .line 68
    :cond_1
    return-object v2

    .line 69
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 70
    .line 71
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    iget-object p0, p0, La71/b0;->f:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast p0, Lvy0/b0;

    .line 77
    .line 78
    new-instance v8, Lny/f0;

    .line 79
    .line 80
    move-object v10, v7

    .line 81
    check-cast v10, Lq1/e;

    .line 82
    .line 83
    move-object v11, v6

    .line 84
    check-cast v11, Lv3/f1;

    .line 85
    .line 86
    move-object v12, v5

    .line 87
    check-cast v12, La4/b;

    .line 88
    .line 89
    const/16 v9, 0x9

    .line 90
    .line 91
    const/4 v13, 0x0

    .line 92
    invoke-direct/range {v8 .. v13}, Lny/f0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 93
    .line 94
    .line 95
    invoke-static {p0, v13, v13, v8, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 96
    .line 97
    .line 98
    new-instance p1, Lna/e;

    .line 99
    .line 100
    check-cast v4, Lc41/b;

    .line 101
    .line 102
    const/16 v0, 0x12

    .line 103
    .line 104
    invoke-direct {p1, v0, v10, v4, v13}, Lna/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 105
    .line 106
    .line 107
    invoke-static {p0, v13, v13, p1, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    return-object p0

    .line 112
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 113
    .line 114
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    iget-object p0, p0, La71/b0;->f:Ljava/lang/Object;

    .line 118
    .line 119
    check-cast p0, Ljava/lang/Long;

    .line 120
    .line 121
    if-eqz p0, :cond_3

    .line 122
    .line 123
    check-cast v7, Li2/z;

    .line 124
    .line 125
    check-cast v6, Li2/e0;

    .line 126
    .line 127
    check-cast v5, Ljava/util/Locale;

    .line 128
    .line 129
    check-cast v4, Ll2/b1;

    .line 130
    .line 131
    invoke-virtual {p0}, Ljava/lang/Number;->longValue()J

    .line 132
    .line 133
    .line 134
    move-result-wide p0

    .line 135
    iget-object v0, v6, Li2/e0;->c:Ljava/lang/String;

    .line 136
    .line 137
    check-cast v7, Li2/b0;

    .line 138
    .line 139
    sget-object v1, Li2/b0;->e:Ljava/time/ZoneId;

    .line 140
    .line 141
    iget-object v1, v7, Li2/z;->b:Ljava/util/LinkedHashMap;

    .line 142
    .line 143
    invoke-static {v0, v5, v1}, Li2/a1;->i(Ljava/lang/String;Ljava/util/Locale;Ljava/util/Map;)Ljava/time/format/DateTimeFormatter;

    .line 144
    .line 145
    .line 146
    move-result-object v0

    .line 147
    invoke-static {p0, p1}, Ljava/time/Instant;->ofEpochMilli(J)Ljava/time/Instant;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    sget-object p1, Li2/b0;->e:Ljava/time/ZoneId;

    .line 152
    .line 153
    invoke-virtual {p0, p1}, Ljava/time/Instant;->atZone(Ljava/time/ZoneId;)Ljava/time/ZonedDateTime;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    invoke-virtual {p0}, Ljava/time/ZonedDateTime;->toLocalDate()Ljava/time/LocalDate;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    invoke-virtual {p0, v0}, Ljava/time/LocalDate;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    new-instance p1, Ll4/v;

    .line 166
    .line 167
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 168
    .line 169
    .line 170
    move-result v0

    .line 171
    if-nez v0, :cond_2

    .line 172
    .line 173
    sget-wide v0, Lg4/o0;->b:J

    .line 174
    .line 175
    goto :goto_0

    .line 176
    :cond_2
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 177
    .line 178
    .line 179
    move-result v0

    .line 180
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 181
    .line 182
    .line 183
    move-result v1

    .line 184
    invoke-static {v0, v1}, Lg4/f0;->b(II)J

    .line 185
    .line 186
    .line 187
    move-result-wide v0

    .line 188
    :goto_0
    const/4 v3, 0x4

    .line 189
    invoke-direct {p1, v0, v1, p0, v3}, Ll4/v;-><init>(JLjava/lang/String;I)V

    .line 190
    .line 191
    .line 192
    sget-object p0, Lh2/x1;->a:Lk1/a1;

    .line 193
    .line 194
    invoke-interface {v4, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    :cond_3
    return-object v2

    .line 198
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 199
    .line 200
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 201
    .line 202
    .line 203
    iget-object p0, p0, La71/b0;->f:Ljava/lang/Object;

    .line 204
    .line 205
    check-cast p0, Lce/j;

    .line 206
    .line 207
    sget-object p1, Lce/g;->a:Lce/g;

    .line 208
    .line 209
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 210
    .line 211
    .line 212
    move-result p1

    .line 213
    if-eqz p1, :cond_4

    .line 214
    .line 215
    check-cast v4, Ll2/b1;

    .line 216
    .line 217
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    move-result-object p0

    .line 221
    check-cast p0, Lay0/a;

    .line 222
    .line 223
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    goto :goto_1

    .line 227
    :cond_4
    instance-of p1, p0, Lce/h;

    .line 228
    .line 229
    if-nez p1, :cond_7

    .line 230
    .line 231
    sget-object p1, Lce/i;->a:Lce/i;

    .line 232
    .line 233
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 234
    .line 235
    .line 236
    move-result p1

    .line 237
    if-eqz p1, :cond_5

    .line 238
    .line 239
    check-cast v5, Ll2/b1;

    .line 240
    .line 241
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object p0

    .line 245
    check-cast p0, Lay0/a;

    .line 246
    .line 247
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    goto :goto_1

    .line 251
    :cond_5
    if-nez p0, :cond_6

    .line 252
    .line 253
    :goto_1
    check-cast v7, Lce/u;

    .line 254
    .line 255
    iget-object p0, v7, Lce/u;->f:Lyy0/c2;

    .line 256
    .line 257
    invoke-virtual {p0, v3}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 258
    .line 259
    .line 260
    return-object v2

    .line 261
    :cond_6
    new-instance p0, La8/r0;

    .line 262
    .line 263
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 264
    .line 265
    .line 266
    throw p0

    .line 267
    :cond_7
    check-cast v6, Ll2/b1;

    .line 268
    .line 269
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    move-result-object p0

    .line 273
    check-cast p0, Lay0/k;

    .line 274
    .line 275
    throw v3

    .line 276
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 277
    .line 278
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 279
    .line 280
    .line 281
    iget-object p0, p0, La71/b0;->f:Ljava/lang/Object;

    .line 282
    .line 283
    check-cast p0, Lag/k;

    .line 284
    .line 285
    instance-of p1, p0, Lag/i;

    .line 286
    .line 287
    sget-object v0, Lag/h;->a:Lag/h;

    .line 288
    .line 289
    if-eqz p1, :cond_8

    .line 290
    .line 291
    check-cast v4, Ll2/b1;

    .line 292
    .line 293
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 294
    .line 295
    .line 296
    move-result-object p0

    .line 297
    check-cast p0, Lay0/k;

    .line 298
    .line 299
    invoke-interface {p0, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 300
    .line 301
    .line 302
    goto :goto_2

    .line 303
    :cond_8
    sget-object p1, Lag/j;->a:Lag/j;

    .line 304
    .line 305
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 306
    .line 307
    .line 308
    move-result p1

    .line 309
    if-eqz p1, :cond_9

    .line 310
    .line 311
    check-cast v6, Ll2/b1;

    .line 312
    .line 313
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object p0

    .line 317
    check-cast p0, Lay0/a;

    .line 318
    .line 319
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 320
    .line 321
    .line 322
    goto :goto_2

    .line 323
    :cond_9
    sget-object p1, Lag/g;->a:Lag/g;

    .line 324
    .line 325
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 326
    .line 327
    .line 328
    move-result p1

    .line 329
    if-eqz p1, :cond_a

    .line 330
    .line 331
    check-cast v5, Ll2/b1;

    .line 332
    .line 333
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    move-result-object p0

    .line 337
    check-cast p0, Lay0/a;

    .line 338
    .line 339
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 340
    .line 341
    .line 342
    goto :goto_2

    .line 343
    :cond_a
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 344
    .line 345
    .line 346
    move-result p0

    .line 347
    if-eqz p0, :cond_c

    .line 348
    .line 349
    :goto_2
    check-cast v7, Lag/u;

    .line 350
    .line 351
    iget-object p0, v7, Lag/u;->g:Lyy0/c2;

    .line 352
    .line 353
    :cond_b
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 354
    .line 355
    .line 356
    move-result-object p1

    .line 357
    move-object v1, p1

    .line 358
    check-cast v1, Lag/w;

    .line 359
    .line 360
    const/16 v4, 0xf

    .line 361
    .line 362
    invoke-static {v1, v3, v3, v0, v4}, Lag/w;->a(Lag/w;Llc/q;Ljp/a1;Lag/k;I)Lag/w;

    .line 363
    .line 364
    .line 365
    move-result-object v1

    .line 366
    invoke-virtual {p0, p1, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 367
    .line 368
    .line 369
    move-result p1

    .line 370
    if-eqz p1, :cond_b

    .line 371
    .line 372
    return-object v2

    .line 373
    :cond_c
    new-instance p0, La8/r0;

    .line 374
    .line 375
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 376
    .line 377
    .line 378
    throw p0

    .line 379
    :pswitch_4
    iget-object p0, p0, La71/b0;->f:Ljava/lang/Object;

    .line 380
    .line 381
    check-cast p0, Ld71/c;

    .line 382
    .line 383
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 384
    .line 385
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 386
    .line 387
    .line 388
    check-cast v4, Ll2/b1;

    .line 389
    .line 390
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 391
    .line 392
    .line 393
    move-result-object p1

    .line 394
    check-cast p1, Ld71/a;

    .line 395
    .line 396
    if-eqz p1, :cond_d

    .line 397
    .line 398
    iget-object v0, p0, Ld71/c;->b:Ll2/j1;

    .line 399
    .line 400
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    move-result-object v1

    .line 404
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 405
    .line 406
    .line 407
    move-result p1

    .line 408
    if-eqz p1, :cond_d

    .line 409
    .line 410
    invoke-virtual {v0, v3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 411
    .line 412
    .line 413
    :cond_d
    check-cast v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 414
    .line 415
    if-nez v7, :cond_e

    .line 416
    .line 417
    invoke-interface {v4, v3}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 418
    .line 419
    .line 420
    goto/16 :goto_4

    .line 421
    .line 422
    :cond_e
    instance-of p1, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ScenarioSelectionFailed;

    .line 423
    .line 424
    check-cast v6, Lh71/p;

    .line 425
    .line 426
    check-cast v5, Lh70/o;

    .line 427
    .line 428
    sget-object v0, Ld71/e;->a:Ll2/e0;

    .line 429
    .line 430
    const-string v0, "rpaIcons"

    .line 431
    .line 432
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 433
    .line 434
    .line 435
    const-string v0, "translator"

    .line 436
    .line 437
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 438
    .line 439
    .line 440
    new-instance v0, La71/u;

    .line 441
    .line 442
    const/16 v1, 0x19

    .line 443
    .line 444
    invoke-direct {v0, v7, v1}, La71/u;-><init>(Ljava/lang/Object;I)V

    .line 445
    .line 446
    .line 447
    const-string v1, "SkodaRPAPlugin"

    .line 448
    .line 449
    invoke-static {v1, v3, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logDebug(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 450
    .line 451
    .line 452
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$AirSuspensionHeightNio;

    .line 453
    .line 454
    if-eqz v0, :cond_f

    .line 455
    .line 456
    new-instance v0, Llx0/l;

    .line 457
    .line 458
    const-string v1, "interruption_air_suspension_height_nio_title"

    .line 459
    .line 460
    const-string v6, "interruption_air_suspension_height_nio_text"

    .line 461
    .line 462
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 463
    .line 464
    .line 465
    goto/16 :goto_3

    .line 466
    .line 467
    :cond_f
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$BadConnectionQuality;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$BadConnectionQuality;

    .line 468
    .line 469
    invoke-virtual {v7, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 470
    .line 471
    .line 472
    move-result v0

    .line 473
    if-eqz v0, :cond_10

    .line 474
    .line 475
    new-instance v0, Llx0/l;

    .line 476
    .line 477
    const-string v1, "interruption_bad_connection_quality_title"

    .line 478
    .line 479
    invoke-direct {v0, v1, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 480
    .line 481
    .line 482
    goto/16 :goto_3

    .line 483
    .line 484
    :cond_10
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ChargeLevelLow;

    .line 485
    .line 486
    if-eqz v0, :cond_11

    .line 487
    .line 488
    new-instance v0, Llx0/l;

    .line 489
    .line 490
    const-string v1, "interruption_charge_level_low_title"

    .line 491
    .line 492
    const-string v6, "interruption_charge_level_low_text"

    .line 493
    .line 494
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 495
    .line 496
    .line 497
    goto/16 :goto_3

    .line 498
    .line 499
    :cond_11
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ChargingPlugPlugged;

    .line 500
    .line 501
    if-eqz v0, :cond_12

    .line 502
    .line 503
    new-instance v0, Llx0/l;

    .line 504
    .line 505
    const-string v1, "interruption_charging_plug_plugged_title"

    .line 506
    .line 507
    const-string v6, "interruption_charging_plug_plugged_text"

    .line 508
    .line 509
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 510
    .line 511
    .line 512
    goto/16 :goto_3

    .line 513
    .line 514
    :cond_12
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$CountryNotAllowed;

    .line 515
    .line 516
    if-eqz v0, :cond_13

    .line 517
    .line 518
    new-instance v0, Llx0/l;

    .line 519
    .line 520
    const-string v1, "interruption_country_not_allowed_title"

    .line 521
    .line 522
    const-string v6, "interruption_country_not_allowed_text"

    .line 523
    .line 524
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 525
    .line 526
    .line 527
    goto/16 :goto_3

    .line 528
    .line 529
    :cond_13
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$DoorsAndFlaps;

    .line 530
    .line 531
    if-eqz v0, :cond_14

    .line 532
    .line 533
    new-instance v0, Llx0/l;

    .line 534
    .line 535
    const-string v1, "interruption_doors_and_flaps_title"

    .line 536
    .line 537
    const-string v6, "interruption_doors_and_flaps_text"

    .line 538
    .line 539
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 540
    .line 541
    .line 542
    goto/16 :goto_3

    .line 543
    .line 544
    :cond_14
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$DriveActivationThresholdNotReached;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$DriveActivationThresholdNotReached;

    .line 545
    .line 546
    invoke-virtual {v7, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 547
    .line 548
    .line 549
    move-result v0

    .line 550
    if-eqz v0, :cond_15

    .line 551
    .line 552
    new-instance v0, Llx0/l;

    .line 553
    .line 554
    const-string v1, "parking_failed_connection_lost_title"

    .line 555
    .line 556
    const-string v6, "parking_failed_connection_lost_text"

    .line 557
    .line 558
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 559
    .line 560
    .line 561
    goto/16 :goto_3

    .line 562
    .line 563
    :cond_15
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$FunctionNotAvailable;

    .line 564
    .line 565
    if-eqz v0, :cond_16

    .line 566
    .line 567
    new-instance v0, Llx0/l;

    .line 568
    .line 569
    const-string v1, "interruption_function_not_available_title"

    .line 570
    .line 571
    const-string v6, "interruption_function_not_available_text"

    .line 572
    .line 573
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 574
    .line 575
    .line 576
    goto/16 :goto_3

    .line 577
    .line 578
    :cond_16
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$GarageDoorOpen;

    .line 579
    .line 580
    if-eqz v0, :cond_17

    .line 581
    .line 582
    new-instance v0, Llx0/l;

    .line 583
    .line 584
    const-string v1, "interruption_garage_door_open_title"

    .line 585
    .line 586
    const-string v6, "interruption_garage_door_open_text"

    .line 587
    .line 588
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 589
    .line 590
    .line 591
    goto/16 :goto_3

    .line 592
    .line 593
    :cond_17
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$InteractionDetected;

    .line 594
    .line 595
    if-eqz v0, :cond_18

    .line 596
    .line 597
    new-instance v0, Llx0/l;

    .line 598
    .line 599
    const-string v1, "interruption_interaction_detected_title"

    .line 600
    .line 601
    const-string v6, "interruption_interaction_detected_text"

    .line 602
    .line 603
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 604
    .line 605
    .line 606
    goto/16 :goto_3

    .line 607
    .line 608
    :cond_18
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$InternalPPErrorKeyAuthorizerOrMalfunction;

    .line 609
    .line 610
    const-string v1, "interruption_pp_error_key_authorizer_text"

    .line 611
    .line 612
    const-string v6, "interruption_pp_error_key_authorizer_title"

    .line 613
    .line 614
    if-eqz v0, :cond_19

    .line 615
    .line 616
    new-instance v0, Llx0/l;

    .line 617
    .line 618
    invoke-direct {v0, v6, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 619
    .line 620
    .line 621
    goto/16 :goto_3

    .line 622
    .line 623
    :cond_19
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$IntrusionVehicleSystem;

    .line 624
    .line 625
    if-eqz v0, :cond_1a

    .line 626
    .line 627
    new-instance v0, Llx0/l;

    .line 628
    .line 629
    const-string v1, "interruption_intervention_vehicle_system_title"

    .line 630
    .line 631
    const-string v6, "interruption_intervention_vehicle_system_text"

    .line 632
    .line 633
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 634
    .line 635
    .line 636
    goto/16 :goto_3

    .line 637
    .line 638
    :cond_1a
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KABVokoVkmOn;

    .line 639
    .line 640
    if-eqz v0, :cond_1b

    .line 641
    .line 642
    new-instance v0, Llx0/l;

    .line 643
    .line 644
    const-string v1, "interruption_kab_voko_vkm_on_title"

    .line 645
    .line 646
    const-string v6, "interruption_kab_voko_vkm_on_text"

    .line 647
    .line 648
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 649
    .line 650
    .line 651
    goto/16 :goto_3

    .line 652
    .line 653
    :cond_1b
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KABVovoVkmOff;

    .line 654
    .line 655
    if-eqz v0, :cond_1c

    .line 656
    .line 657
    new-instance v0, Llx0/l;

    .line 658
    .line 659
    const-string v1, "interruption_kab_voko_vkm_off_title"

    .line 660
    .line 661
    const-string v6, "interruption_kab_voko_vkm_off_text"

    .line 662
    .line 663
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 664
    .line 665
    .line 666
    goto/16 :goto_3

    .line 667
    .line 668
    :cond_1c
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KeyInsideInterior;

    .line 669
    .line 670
    if-eqz v0, :cond_1d

    .line 671
    .line 672
    new-instance v0, Llx0/l;

    .line 673
    .line 674
    const-string v1, "interruption_key_inside_interior_title"

    .line 675
    .line 676
    const-string v6, "interruption_key_inside_interior_text"

    .line 677
    .line 678
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 679
    .line 680
    .line 681
    goto/16 :goto_3

    .line 682
    .line 683
    :cond_1d
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KeyOutOfRange;

    .line 684
    .line 685
    if-eqz v0, :cond_1e

    .line 686
    .line 687
    new-instance v0, Llx0/l;

    .line 688
    .line 689
    const-string v1, "interruption_key_out_of_range_title"

    .line 690
    .line 691
    const-string v6, "interruption_key_out_of_range_text"

    .line 692
    .line 693
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 694
    .line 695
    .line 696
    goto/16 :goto_3

    .line 697
    .line 698
    :cond_1e
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KeySwitchOperated;

    .line 699
    .line 700
    if-eqz v0, :cond_1f

    .line 701
    .line 702
    new-instance v0, Llx0/l;

    .line 703
    .line 704
    const-string v1, "interruption_key_switch_operated_title"

    .line 705
    .line 706
    const-string v6, "interruption_key_switch_operated_text"

    .line 707
    .line 708
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 709
    .line 710
    .line 711
    goto/16 :goto_3

    .line 712
    .line 713
    :cond_1f
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$MalFunction;

    .line 714
    .line 715
    if-eqz v0, :cond_20

    .line 716
    .line 717
    new-instance v0, Llx0/l;

    .line 718
    .line 719
    const-string v1, "interruption_malfunction_title"

    .line 720
    .line 721
    const-string v6, "interruption_malfunction_text"

    .line 722
    .line 723
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 724
    .line 725
    .line 726
    goto/16 :goto_3

    .line 727
    .line 728
    :cond_20
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$MaxDistanceReached;

    .line 729
    .line 730
    if-eqz v0, :cond_21

    .line 731
    .line 732
    new-instance v0, Llx0/l;

    .line 733
    .line 734
    const-string v1, "interruption_max_distance_reached_title"

    .line 735
    .line 736
    const-string v6, "interruption_max_distance_reached_text"

    .line 737
    .line 738
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 739
    .line 740
    .line 741
    goto/16 :goto_3

    .line 742
    .line 743
    :cond_21
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$MaxMovesReached;

    .line 744
    .line 745
    if-eqz v0, :cond_22

    .line 746
    .line 747
    new-instance v0, Llx0/l;

    .line 748
    .line 749
    const-string v1, "interruption_max_moves_reached_title"

    .line 750
    .line 751
    const-string v6, "interruption_max_moves_reached_text"

    .line 752
    .line 753
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 754
    .line 755
    .line 756
    goto/16 :goto_3

    .line 757
    .line 758
    :cond_22
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$MultiTouch;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$MultiTouch;

    .line 759
    .line 760
    invoke-virtual {v7, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 761
    .line 762
    .line 763
    move-result v0

    .line 764
    if-eqz v0, :cond_23

    .line 765
    .line 766
    new-instance v0, Llx0/l;

    .line 767
    .line 768
    const-string v1, "interruption_multi_touch_detected_title"

    .line 769
    .line 770
    const-string v6, "interruption_multi_touch_detected_text"

    .line 771
    .line 772
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 773
    .line 774
    .line 775
    goto/16 :goto_3

    .line 776
    .line 777
    :cond_23
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$MultipleKeysDetected;

    .line 778
    .line 779
    if-eqz v0, :cond_24

    .line 780
    .line 781
    new-instance v0, Llx0/l;

    .line 782
    .line 783
    const-string v1, "interruption_multiple_keys_detected_title"

    .line 784
    .line 785
    const-string v6, "interruption_multiple_keys_detected_text"

    .line 786
    .line 787
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 788
    .line 789
    .line 790
    goto/16 :goto_3

    .line 791
    .line 792
    :cond_24
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$NoContinuationOfTheJourney;

    .line 793
    .line 794
    if-eqz v0, :cond_25

    .line 795
    .line 796
    new-instance v0, Llx0/l;

    .line 797
    .line 798
    const-string v1, "interruption_no_continuation_of_the_journey_title"

    .line 799
    .line 800
    const-string v6, "interruption_no_continuation_of_the_journey_text"

    .line 801
    .line 802
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 803
    .line 804
    .line 805
    goto/16 :goto_3

    .line 806
    .line 807
    :cond_25
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ObstacleDetected;

    .line 808
    .line 809
    if-eqz v0, :cond_26

    .line 810
    .line 811
    new-instance v0, Llx0/l;

    .line 812
    .line 813
    const-string v1, "interruption_obstacle_detected_title"

    .line 814
    .line 815
    const-string v6, "interruption_obstacle_detected_text"

    .line 816
    .line 817
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 818
    .line 819
    .line 820
    goto/16 :goto_3

    .line 821
    .line 822
    :cond_26
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$OffRoadActive;

    .line 823
    .line 824
    if-eqz v0, :cond_27

    .line 825
    .line 826
    new-instance v0, Llx0/l;

    .line 827
    .line 828
    const-string v1, "interruption_off_road_active_title"

    .line 829
    .line 830
    const-string v6, "interruption_off_road_active_text"

    .line 831
    .line 832
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 833
    .line 834
    .line 835
    goto/16 :goto_3

    .line 836
    .line 837
    :cond_27
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$PPErrorKeyAuthorizer;

    .line 838
    .line 839
    if-eqz v0, :cond_28

    .line 840
    .line 841
    new-instance v0, Llx0/l;

    .line 842
    .line 843
    invoke-direct {v0, v6, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 844
    .line 845
    .line 846
    goto/16 :goto_3

    .line 847
    .line 848
    :cond_28
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$PPLossPOSOK;

    .line 849
    .line 850
    if-eqz v0, :cond_29

    .line 851
    .line 852
    new-instance v0, Llx0/l;

    .line 853
    .line 854
    const-string v1, "interruption_pp_loss_pos_ok_title"

    .line 855
    .line 856
    const-string v6, "interruption_pp_loss_pos_ok_text"

    .line 857
    .line 858
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 859
    .line 860
    .line 861
    goto/16 :goto_3

    .line 862
    .line 863
    :cond_29
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ParkingSpaceTooSmall;

    .line 864
    .line 865
    if-eqz v0, :cond_2a

    .line 866
    .line 867
    new-instance v0, Llx0/l;

    .line 868
    .line 869
    const-string v1, "interruption_parking_space_too_small_title"

    .line 870
    .line 871
    const-string v6, "interruption_parking_space_too_small_text"

    .line 872
    .line 873
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 874
    .line 875
    .line 876
    goto/16 :goto_3

    .line 877
    .line 878
    :cond_2a
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ReceptionObstructed;

    .line 879
    .line 880
    if-eqz v0, :cond_2b

    .line 881
    .line 882
    new-instance v0, Llx0/l;

    .line 883
    .line 884
    const-string v1, "interruption_reception_obstructed_title"

    .line 885
    .line 886
    const-string v6, "interruption_reception_obstructed_text"

    .line 887
    .line 888
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 889
    .line 890
    .line 891
    goto/16 :goto_3

    .line 892
    .line 893
    :cond_2b
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ReverseNotPossible;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ReverseNotPossible;

    .line 894
    .line 895
    invoke-virtual {v7, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 896
    .line 897
    .line 898
    move-result v0

    .line 899
    if-eqz v0, :cond_2c

    .line 900
    .line 901
    new-instance v0, Llx0/l;

    .line 902
    .line 903
    const-string v1, "interruption_reverse_not_possible_title"

    .line 904
    .line 905
    const-string v6, "interruption_reverse_not_possible_text"

    .line 906
    .line 907
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 908
    .line 909
    .line 910
    goto/16 :goto_3

    .line 911
    .line 912
    :cond_2c
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$RouteNotTrained;

    .line 913
    .line 914
    if-eqz v0, :cond_2d

    .line 915
    .line 916
    new-instance v0, Llx0/l;

    .line 917
    .line 918
    const-string v1, "interruption_route_not_trained_title"

    .line 919
    .line 920
    const-string v6, "interruption_route_not_trained_text"

    .line 921
    .line 922
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 923
    .line 924
    .line 925
    goto/16 :goto_3

    .line 926
    .line 927
    :cond_2d
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ScenarioSelectionFailed;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ScenarioSelectionFailed;

    .line 928
    .line 929
    invoke-virtual {v7, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 930
    .line 931
    .line 932
    move-result v0

    .line 933
    if-eqz v0, :cond_2e

    .line 934
    .line 935
    new-instance v0, Llx0/l;

    .line 936
    .line 937
    const-string v1, "interruption_scenario_selection_failed_title"

    .line 938
    .line 939
    const-string v6, "interruption_scenario_selection_failed_text"

    .line 940
    .line 941
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 942
    .line 943
    .line 944
    goto/16 :goto_3

    .line 945
    .line 946
    :cond_2e
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ShuntingAreaTooSmall;

    .line 947
    .line 948
    if-eqz v0, :cond_2f

    .line 949
    .line 950
    new-instance v0, Llx0/l;

    .line 951
    .line 952
    const-string v1, "interruption_shunting_area_too_small_title"

    .line 953
    .line 954
    const-string v6, "interruption_shunting_area_too_small_text"

    .line 955
    .line 956
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 957
    .line 958
    .line 959
    goto/16 :goto_3

    .line 960
    .line 961
    :cond_2f
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$StandbyIncreasedDrivingResistance;

    .line 962
    .line 963
    if-eqz v0, :cond_30

    .line 964
    .line 965
    new-instance v0, Llx0/l;

    .line 966
    .line 967
    const-string v1, "interruption_standby_increased_driving_resistance_title"

    .line 968
    .line 969
    const-string v6, "interruption_standby_increased_driving_resistance_text"

    .line 970
    .line 971
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 972
    .line 973
    .line 974
    goto :goto_3

    .line 975
    :cond_30
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TerminationByGWSM;

    .line 976
    .line 977
    if-eqz v0, :cond_31

    .line 978
    .line 979
    new-instance v0, Llx0/l;

    .line 980
    .line 981
    const-string v1, "interruption_termination_by_gwsm_title"

    .line 982
    .line 983
    const-string v6, "interruption_termination_by_gwsm_text"

    .line 984
    .line 985
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 986
    .line 987
    .line 988
    goto :goto_3

    .line 989
    :cond_31
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TerminationEscIntervention;

    .line 990
    .line 991
    if-eqz v0, :cond_32

    .line 992
    .line 993
    new-instance v0, Llx0/l;

    .line 994
    .line 995
    const-string v1, "interruption_termination_esc_intervention_title"

    .line 996
    .line 997
    const-string v6, "interruption_termination_esc_intervention_text"

    .line 998
    .line 999
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 1000
    .line 1001
    .line 1002
    goto :goto_3

    .line 1003
    :cond_32
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TerminationIncreasedDrivingResistance;

    .line 1004
    .line 1005
    if-eqz v0, :cond_33

    .line 1006
    .line 1007
    new-instance v0, Llx0/l;

    .line 1008
    .line 1009
    const-string v1, "interruption_termination_increased_driving_resistance_title"

    .line 1010
    .line 1011
    const-string v6, "interruption_termination_increased_driving_resistance_text"

    .line 1012
    .line 1013
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 1014
    .line 1015
    .line 1016
    goto :goto_3

    .line 1017
    :cond_33
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TerminationTSKGradient;

    .line 1018
    .line 1019
    if-eqz v0, :cond_34

    .line 1020
    .line 1021
    new-instance v0, Llx0/l;

    .line 1022
    .line 1023
    const-string v1, "interruption_termination_tsk_gradient_title"

    .line 1024
    .line 1025
    const-string v6, "interruption_termination_tsk_gradient_text"

    .line 1026
    .line 1027
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 1028
    .line 1029
    .line 1030
    goto :goto_3

    .line 1031
    :cond_34
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$Timeout;

    .line 1032
    .line 1033
    if-eqz v0, :cond_35

    .line 1034
    .line 1035
    new-instance v0, Llx0/l;

    .line 1036
    .line 1037
    const-string v1, "interruption_timeout_title"

    .line 1038
    .line 1039
    const-string v6, "interruption_timeout_text"

    .line 1040
    .line 1041
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 1042
    .line 1043
    .line 1044
    goto :goto_3

    .line 1045
    :cond_35
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TrafficDetected;

    .line 1046
    .line 1047
    if-eqz v0, :cond_36

    .line 1048
    .line 1049
    new-instance v0, Llx0/l;

    .line 1050
    .line 1051
    const-string v1, "interruption_traffic_detected_title"

    .line 1052
    .line 1053
    const-string v6, "interruption_traffic_detected_text"

    .line 1054
    .line 1055
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 1056
    .line 1057
    .line 1058
    goto :goto_3

    .line 1059
    :cond_36
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$TrailerDetected;

    .line 1060
    .line 1061
    if-eqz v0, :cond_38

    .line 1062
    .line 1063
    new-instance v0, Llx0/l;

    .line 1064
    .line 1065
    const-string v1, "interruption_trailer_detected_title"

    .line 1066
    .line 1067
    const-string v6, "interruption_trailer_detected_text"

    .line 1068
    .line 1069
    invoke-direct {v0, v1, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 1070
    .line 1071
    .line 1072
    :goto_3
    iget-object v1, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 1073
    .line 1074
    check-cast v1, Ljava/lang/String;

    .line 1075
    .line 1076
    iget-object v0, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 1077
    .line 1078
    check-cast v0, Ljava/lang/String;

    .line 1079
    .line 1080
    const-string v6, "titleId"

    .line 1081
    .line 1082
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1083
    .line 1084
    .line 1085
    invoke-virtual {v5, v1}, Lh70/o;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 1086
    .line 1087
    .line 1088
    move-result-object v1

    .line 1089
    if-eqz v0, :cond_37

    .line 1090
    .line 1091
    invoke-virtual {v5, v0}, Lh70/o;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 1092
    .line 1093
    .line 1094
    move-result-object v3

    .line 1095
    :cond_37
    new-instance v0, Ld71/a;

    .line 1096
    .line 1097
    invoke-direct {v0, v1, v3, p1}, Ld71/a;-><init>(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 1098
    .line 1099
    .line 1100
    invoke-interface {v4, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 1101
    .line 1102
    .line 1103
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1104
    .line 1105
    .line 1106
    iget-object p1, p0, Ld71/c;->b:Ll2/j1;

    .line 1107
    .line 1108
    invoke-virtual {p1, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 1109
    .line 1110
    .line 1111
    iget-object p0, p0, Ld71/c;->a:Ll2/j1;

    .line 1112
    .line 1113
    invoke-virtual {p0, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 1114
    .line 1115
    .line 1116
    :goto_4
    return-object v2

    .line 1117
    :cond_38
    new-instance p0, La8/r0;

    .line 1118
    .line 1119
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1120
    .line 1121
    .line 1122
    throw p0

    .line 1123
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
