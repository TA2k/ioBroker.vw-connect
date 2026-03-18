.class public final Ltz/u;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ltz/n0;


# direct methods
.method public synthetic constructor <init>(Ltz/n0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ltz/u;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/u;->g:Ltz/n0;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Ltz/u;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ltz/u;

    .line 7
    .line 8
    iget-object p0, p0, Ltz/u;->g:Ltz/n0;

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    invoke-direct {v0, p0, p2, v1}, Ltz/u;-><init>(Ltz/n0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Ltz/u;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Ltz/u;

    .line 18
    .line 19
    iget-object p0, p0, Ltz/u;->g:Ltz/n0;

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    invoke-direct {v0, p0, p2, v1}, Ltz/u;-><init>(Ltz/n0;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Ltz/u;->f:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Ltz/u;

    .line 29
    .line 30
    iget-object p0, p0, Ltz/u;->g:Ltz/n0;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    invoke-direct {v0, p0, p2, v1}, Ltz/u;-><init>(Ltz/n0;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    iput-object p1, v0, Ltz/u;->f:Ljava/lang/Object;

    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ltz/u;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/c;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Ltz/u;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ltz/u;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ltz/u;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lne0/c;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Ltz/u;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Ltz/u;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Ltz/u;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Llx0/l;

    .line 41
    .line 42
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Ltz/u;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Ltz/u;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Ltz/u;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Ltz/u;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltz/u;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lne0/c;

    .line 9
    .line 10
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v2, p0, Ltz/u;->e:I

    .line 13
    .line 14
    const/4 v3, 0x1

    .line 15
    if-eqz v2, :cond_1

    .line 16
    .line 17
    if-ne v2, v3, :cond_0

    .line 18
    .line 19
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    iget-object p1, p0, Ltz/u;->g:Ltz/n0;

    .line 35
    .line 36
    iget-object p1, p1, Ltz/n0;->G:Lko0/f;

    .line 37
    .line 38
    const/4 v2, 0x0

    .line 39
    iput-object v2, p0, Ltz/u;->f:Ljava/lang/Object;

    .line 40
    .line 41
    iput v3, p0, Ltz/u;->e:I

    .line 42
    .line 43
    invoke-virtual {p1, v0, p0}, Lko0/f;->b(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    if-ne p0, v1, :cond_2

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_2
    :goto_0
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    :goto_1
    return-object v1

    .line 53
    :pswitch_0
    iget-object v0, p0, Ltz/u;->f:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v0, Lne0/c;

    .line 56
    .line 57
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 58
    .line 59
    iget v2, p0, Ltz/u;->e:I

    .line 60
    .line 61
    const/4 v3, 0x1

    .line 62
    if-eqz v2, :cond_4

    .line 63
    .line 64
    if-ne v2, v3, :cond_3

    .line 65
    .line 66
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 71
    .line 72
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 73
    .line 74
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    throw p0

    .line 78
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    iget-object p1, p0, Ltz/u;->g:Ltz/n0;

    .line 82
    .line 83
    iget-object p1, p1, Ltz/n0;->G:Lko0/f;

    .line 84
    .line 85
    const/4 v2, 0x0

    .line 86
    iput-object v2, p0, Ltz/u;->f:Ljava/lang/Object;

    .line 87
    .line 88
    iput v3, p0, Ltz/u;->e:I

    .line 89
    .line 90
    invoke-virtual {p1, v0, p0}, Lko0/f;->b(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    if-ne p0, v1, :cond_5

    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_5
    :goto_2
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 98
    .line 99
    :goto_3
    return-object v1

    .line 100
    :pswitch_1
    iget-object v0, p0, Ltz/u;->f:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast v0, Llx0/l;

    .line 103
    .line 104
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 105
    .line 106
    iget v2, p0, Ltz/u;->e:I

    .line 107
    .line 108
    const/4 v3, 0x1

    .line 109
    if-eqz v2, :cond_7

    .line 110
    .line 111
    if-ne v2, v3, :cond_6

    .line 112
    .line 113
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    goto :goto_4

    .line 117
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 118
    .line 119
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 120
    .line 121
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    throw p0

    .line 125
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    iget-object p1, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 129
    .line 130
    check-cast p1, Ljava/lang/Boolean;

    .line 131
    .line 132
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 133
    .line 134
    .line 135
    move-result p1

    .line 136
    iget-object v0, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast v0, Lss0/b;

    .line 139
    .line 140
    const/4 v2, 0x0

    .line 141
    iput-object v2, p0, Ltz/u;->f:Ljava/lang/Object;

    .line 142
    .line 143
    iput v3, p0, Ltz/u;->e:I

    .line 144
    .line 145
    iget-object v2, p0, Ltz/u;->g:Ltz/n0;

    .line 146
    .line 147
    invoke-static {v2, p1, v0, p0}, Ltz/n0;->j(Ltz/n0;ZLss0/b;Lrx0/c;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    if-ne p0, v1, :cond_8

    .line 152
    .line 153
    goto :goto_5

    .line 154
    :cond_8
    :goto_4
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 155
    .line 156
    :goto_5
    return-object v1

    .line 157
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
