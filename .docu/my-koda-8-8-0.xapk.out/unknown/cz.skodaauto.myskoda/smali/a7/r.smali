.class public final La7/r;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Landroid/content/Context;

.field public final synthetic h:La7/c;

.field public final synthetic i:La7/m0;


# direct methods
.method public constructor <init>(La7/m0;Landroid/content/Context;La7/c;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, La7/r;->d:I

    .line 1
    iput-object p1, p0, La7/r;->i:La7/m0;

    iput-object p2, p0, La7/r;->g:Landroid/content/Context;

    iput-object p3, p0, La7/r;->h:La7/c;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;La7/c;La7/m0;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, La7/r;->d:I

    .line 2
    iput-object p1, p0, La7/r;->g:Landroid/content/Context;

    iput-object p2, p0, La7/r;->h:La7/c;

    iput-object p3, p0, La7/r;->i:La7/m0;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, La7/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, La7/r;

    .line 7
    .line 8
    iget-object v1, p0, La7/r;->h:La7/c;

    .line 9
    .line 10
    iget-object v2, p0, La7/r;->i:La7/m0;

    .line 11
    .line 12
    iget-object p0, p0, La7/r;->g:Landroid/content/Context;

    .line 13
    .line 14
    invoke-direct {v0, p0, v1, v2, p2}, La7/r;-><init>(Landroid/content/Context;La7/c;La7/m0;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    iput-object p1, v0, La7/r;->f:Ljava/lang/Object;

    .line 18
    .line 19
    return-object v0

    .line 20
    :pswitch_0
    new-instance v0, La7/r;

    .line 21
    .line 22
    iget-object v1, p0, La7/r;->g:Landroid/content/Context;

    .line 23
    .line 24
    iget-object v2, p0, La7/r;->h:La7/c;

    .line 25
    .line 26
    iget-object p0, p0, La7/r;->i:La7/m0;

    .line 27
    .line 28
    invoke-direct {v0, p0, v1, v2, p2}, La7/r;-><init>(La7/m0;Landroid/content/Context;La7/c;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    iput-object p1, v0, La7/r;->f:Ljava/lang/Object;

    .line 32
    .line 33
    return-object v0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, La7/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lh7/l;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, La7/r;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, La7/r;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, La7/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lxy0/x;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, La7/r;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, La7/r;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, La7/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, La7/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, La7/r;->h:La7/c;

    .line 7
    .line 8
    iget v1, v0, La7/c;->a:I

    .line 9
    .line 10
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v3, p0, La7/r;->e:I

    .line 13
    .line 14
    iget-object v4, p0, La7/r;->g:Landroid/content/Context;

    .line 15
    .line 16
    const/4 v5, 0x3

    .line 17
    const/4 v6, 0x2

    .line 18
    const/4 v7, 0x1

    .line 19
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    if-eqz v3, :cond_4

    .line 22
    .line 23
    if-eq v3, v7, :cond_3

    .line 24
    .line 25
    if-eq v3, v6, :cond_0

    .line 26
    .line 27
    if-ne v3, v5, :cond_2

    .line 28
    .line 29
    :cond_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    :cond_1
    move-object v2, v8

    .line 33
    goto :goto_2

    .line 34
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 35
    .line 36
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 37
    .line 38
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw p0

    .line 42
    :cond_3
    iget-object v3, p0, La7/r;->f:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v3, Lh7/l;

    .line 45
    .line 46
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iget-object p1, p0, La7/r;->f:Ljava/lang/Object;

    .line 54
    .line 55
    move-object v3, p1

    .line 56
    check-cast v3, Lh7/l;

    .line 57
    .line 58
    invoke-static {v1}, Lcy0/a;->f(I)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    iput-object v3, p0, La7/r;->f:Ljava/lang/Object;

    .line 63
    .line 64
    iput v7, p0, La7/r;->e:I

    .line 65
    .line 66
    invoke-virtual {v3, v4, p1, p0}, Lh7/l;->a(Landroid/content/Context;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    if-ne p1, v2, :cond_5

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_5
    :goto_0
    check-cast p1, Ljava/lang/Boolean;

    .line 74
    .line 75
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 76
    .line 77
    .line 78
    move-result p1

    .line 79
    const/4 v7, 0x0

    .line 80
    if-nez p1, :cond_6

    .line 81
    .line 82
    new-instance p1, La7/n;

    .line 83
    .line 84
    iget-object v1, p0, La7/r;->i:La7/m0;

    .line 85
    .line 86
    const/16 v5, 0xf8

    .line 87
    .line 88
    invoke-direct {p1, v1, v0, v7, v5}, La7/n;-><init>(La7/m0;La7/c;Landroid/os/Bundle;I)V

    .line 89
    .line 90
    .line 91
    iput-object v7, p0, La7/r;->f:Ljava/lang/Object;

    .line 92
    .line 93
    iput v6, p0, La7/r;->e:I

    .line 94
    .line 95
    invoke-virtual {v3, v4, p1, p0}, Lh7/l;->b(Landroid/content/Context;La7/n;Lrx0/c;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    if-ne p0, v2, :cond_1

    .line 100
    .line 101
    goto :goto_2

    .line 102
    :cond_6
    invoke-static {v1}, Lcy0/a;->f(I)Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    iget-object v0, v3, Lh7/l;->a:Ljava/util/LinkedHashMap;

    .line 107
    .line 108
    invoke-virtual {v0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    check-cast p1, La7/n;

    .line 113
    .line 114
    const-string v0, "null cannot be cast to non-null type androidx.glance.appwidget.AppWidgetSession"

    .line 115
    .line 116
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    iput-object v7, p0, La7/r;->f:Ljava/lang/Object;

    .line 120
    .line 121
    iput v5, p0, La7/r;->e:I

    .line 122
    .line 123
    sget-object v0, La7/f;->a:La7/f;

    .line 124
    .line 125
    invoke-virtual {p1, v0, p0}, La7/n;->e(Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    if-ne p0, v2, :cond_7

    .line 130
    .line 131
    goto :goto_1

    .line 132
    :cond_7
    move-object p0, v8

    .line 133
    :goto_1
    if-ne p0, v2, :cond_1

    .line 134
    .line 135
    :goto_2
    return-object v2

    .line 136
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 137
    .line 138
    iget v1, p0, La7/r;->e:I

    .line 139
    .line 140
    const/4 v2, 0x1

    .line 141
    if-eqz v1, :cond_9

    .line 142
    .line 143
    if-ne v1, v2, :cond_8

    .line 144
    .line 145
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    goto :goto_3

    .line 149
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 150
    .line 151
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 152
    .line 153
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    throw p0

    .line 157
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    iget-object p1, p0, La7/r;->f:Ljava/lang/Object;

    .line 161
    .line 162
    check-cast p1, Lxy0/x;

    .line 163
    .line 164
    new-instance v1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 165
    .line 166
    const/4 v8, 0x0

    .line 167
    invoke-direct {v1, v8}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 168
    .line 169
    .line 170
    new-instance v9, La7/q;

    .line 171
    .line 172
    invoke-direct {v9, v1, p1}, La7/q;-><init>(Ljava/util/concurrent/atomic/AtomicReference;Lxy0/x;)V

    .line 173
    .line 174
    .line 175
    new-instance v3, La7/o;

    .line 176
    .line 177
    iget-object v7, p0, La7/r;->h:La7/c;

    .line 178
    .line 179
    const/4 v4, 0x0

    .line 180
    iget-object v5, p0, La7/r;->i:La7/m0;

    .line 181
    .line 182
    iget-object v6, p0, La7/r;->g:Landroid/content/Context;

    .line 183
    .line 184
    invoke-direct/range {v3 .. v8}, La7/o;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 185
    .line 186
    .line 187
    iput v2, p0, La7/r;->e:I

    .line 188
    .line 189
    invoke-static {v9, v3, p0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object p0

    .line 193
    if-ne p0, v0, :cond_a

    .line 194
    .line 195
    goto :goto_4

    .line 196
    :cond_a
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 197
    .line 198
    :goto_4
    return-object v0

    .line 199
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
