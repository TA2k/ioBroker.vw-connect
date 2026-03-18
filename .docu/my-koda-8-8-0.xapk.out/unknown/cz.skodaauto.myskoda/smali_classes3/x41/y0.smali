.class public final Lx41/y0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lx41/z0;

.field public final synthetic h:Ljava/util/Set;


# direct methods
.method public synthetic constructor <init>(Lx41/z0;Ljava/util/Set;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lx41/y0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lx41/y0;->g:Lx41/z0;

    .line 4
    .line 5
    iput-object p2, p0, Lx41/y0;->h:Ljava/util/Set;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, Lx41/y0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lx41/y0;

    .line 7
    .line 8
    iget-object v1, p0, Lx41/y0;->h:Ljava/util/Set;

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object p0, p0, Lx41/y0;->g:Lx41/z0;

    .line 12
    .line 13
    invoke-direct {v0, p0, v1, p2, v2}, Lx41/y0;-><init>(Lx41/z0;Ljava/util/Set;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Lx41/y0;->f:Ljava/lang/Object;

    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_0
    new-instance v0, Lx41/y0;

    .line 20
    .line 21
    iget-object v1, p0, Lx41/y0;->h:Ljava/util/Set;

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    iget-object p0, p0, Lx41/y0;->g:Lx41/z0;

    .line 25
    .line 26
    invoke-direct {v0, p0, v1, p2, v2}, Lx41/y0;-><init>(Lx41/z0;Ljava/util/Set;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    iput-object p1, v0, Lx41/y0;->f:Ljava/lang/Object;

    .line 30
    .line 31
    return-object v0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lx41/y0;->d:I

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
    invoke-virtual {p0, p1, p2}, Lx41/y0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lx41/y0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lx41/y0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lx41/y0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lx41/y0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lx41/y0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lx41/y0;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const-string v2, "Car2PhonePairing"

    .line 6
    .line 7
    const-class v3, Lx41/n;

    .line 8
    .line 9
    const-class v4, Ljava/util/Set;

    .line 10
    .line 11
    iget-object v5, p0, Lx41/y0;->h:Ljava/util/Set;

    .line 12
    .line 13
    iget-object v6, p0, Lx41/y0;->g:Lx41/z0;

    .line 14
    .line 15
    const-string v7, "call to \'resume\' before \'invoke\' with coroutine"

    .line 16
    .line 17
    const/4 v8, 0x1

    .line 18
    packed-switch v0, :pswitch_data_0

    .line 19
    .line 20
    .line 21
    iget-object v0, p0, Lx41/y0;->f:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v0, Lvy0/b0;

    .line 24
    .line 25
    sget-object v9, Lqx0/a;->d:Lqx0/a;

    .line 26
    .line 27
    iget v10, p0, Lx41/y0;->e:I

    .line 28
    .line 29
    if-eqz v10, :cond_1

    .line 30
    .line 31
    if-ne v10, v8, :cond_0

    .line 32
    .line 33
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    check-cast p1, Llx0/o;

    .line 37
    .line 38
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 42
    .line 43
    invoke-direct {p0, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw p0

    .line 47
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    iget-object p1, v6, Lx41/z0;->a:Lv51/f;

    .line 51
    .line 52
    iget-object v6, v6, Lx41/z0;->f:Ljava/lang/String;

    .line 53
    .line 54
    sget-object v7, Lhy0/d0;->c:Lhy0/d0;

    .line 55
    .line 56
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    invoke-static {v3}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 61
    .line 62
    .line 63
    move-result-object v3

    .line 64
    invoke-static {v4, v3}, Lkotlin/jvm/internal/g0;->c(Ljava/lang/Class;Lhy0/d0;)Lhy0/a0;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    iput-object v0, p0, Lx41/y0;->f:Ljava/lang/Object;

    .line 69
    .line 70
    iput v8, p0, Lx41/y0;->e:I

    .line 71
    .line 72
    invoke-virtual {p1, v6, v5, v3, p0}, Lv51/f;->d(Ljava/lang/String;Ljava/lang/Object;Lhy0/a0;Lrx0/c;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    if-ne p0, v9, :cond_2

    .line 77
    .line 78
    move-object v1, v9

    .line 79
    goto :goto_1

    .line 80
    :cond_2
    :goto_0
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    if-eqz p0, :cond_3

    .line 85
    .line 86
    new-instance p1, Lx41/y;

    .line 87
    .line 88
    const/16 v3, 0x19

    .line 89
    .line 90
    invoke-direct {p1, v3}, Lx41/y;-><init>(I)V

    .line 91
    .line 92
    .line 93
    invoke-static {v0, v2, p0, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 94
    .line 95
    .line 96
    :cond_3
    :goto_1
    return-object v1

    .line 97
    :pswitch_0
    iget-object v0, p0, Lx41/y0;->f:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast v0, Lvy0/b0;

    .line 100
    .line 101
    sget-object v9, Lqx0/a;->d:Lqx0/a;

    .line 102
    .line 103
    iget v10, p0, Lx41/y0;->e:I

    .line 104
    .line 105
    if-eqz v10, :cond_5

    .line 106
    .line 107
    if-ne v10, v8, :cond_4

    .line 108
    .line 109
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    check-cast p1, Llx0/o;

    .line 113
    .line 114
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 118
    .line 119
    invoke-direct {p0, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    throw p0

    .line 123
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    iget-object p1, v6, Lx41/z0;->a:Lv51/f;

    .line 127
    .line 128
    iget-object v6, v6, Lx41/z0;->d:Ljava/lang/String;

    .line 129
    .line 130
    sget-object v7, Lhy0/d0;->c:Lhy0/d0;

    .line 131
    .line 132
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 133
    .line 134
    .line 135
    move-result-object v3

    .line 136
    invoke-static {v3}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 137
    .line 138
    .line 139
    move-result-object v3

    .line 140
    invoke-static {v4, v3}, Lkotlin/jvm/internal/g0;->c(Ljava/lang/Class;Lhy0/d0;)Lhy0/a0;

    .line 141
    .line 142
    .line 143
    move-result-object v3

    .line 144
    iput-object v0, p0, Lx41/y0;->f:Ljava/lang/Object;

    .line 145
    .line 146
    iput v8, p0, Lx41/y0;->e:I

    .line 147
    .line 148
    invoke-virtual {p1, v6, v5, v3, p0}, Lv51/f;->d(Ljava/lang/String;Ljava/lang/Object;Lhy0/a0;Lrx0/c;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    if-ne p0, v9, :cond_6

    .line 153
    .line 154
    move-object v1, v9

    .line 155
    goto :goto_3

    .line 156
    :cond_6
    :goto_2
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    if-eqz p0, :cond_7

    .line 161
    .line 162
    new-instance p1, Lx41/y;

    .line 163
    .line 164
    const/16 v3, 0x18

    .line 165
    .line 166
    invoke-direct {p1, v3}, Lx41/y;-><init>(I)V

    .line 167
    .line 168
    .line 169
    invoke-static {v0, v2, p0, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 170
    .line 171
    .line 172
    :cond_7
    :goto_3
    return-object v1

    .line 173
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
