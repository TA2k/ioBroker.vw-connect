.class public final La10/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:La10/d;

.field public g:Z


# direct methods
.method public constructor <init>(La10/d;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, La10/b;->d:I

    .line 1
    iput-object p1, p0, La10/b;->f:La10/d;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(La10/d;ZLkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, La10/b;->d:I

    .line 2
    iput-object p1, p0, La10/b;->f:La10/d;

    iput-boolean p2, p0, La10/b;->g:Z

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p1, p0, La10/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, La10/b;

    .line 7
    .line 8
    iget-object v0, p0, La10/b;->f:La10/d;

    .line 9
    .line 10
    iget-boolean p0, p0, La10/b;->g:Z

    .line 11
    .line 12
    invoke-direct {p1, v0, p0, p2}, La10/b;-><init>(La10/d;ZLkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-object p1

    .line 16
    :pswitch_0
    new-instance p1, La10/b;

    .line 17
    .line 18
    iget-object p0, p0, La10/b;->f:La10/d;

    .line 19
    .line 20
    invoke-direct {p1, p0, p2}, La10/b;-><init>(La10/d;Lkotlin/coroutines/Continuation;)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, La10/b;->d:I

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
    invoke-virtual {p0, p1, p2}, La10/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, La10/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, La10/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, La10/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, La10/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, La10/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 7

    .line 1
    iget v0, p0, La10/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, La10/b;->g:Z

    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, p0, La10/b;->e:I

    .line 11
    .line 12
    iget-object v3, p0, La10/b;->f:La10/d;

    .line 13
    .line 14
    const/4 v4, 0x1

    .line 15
    if-eqz v2, :cond_1

    .line 16
    .line 17
    if-ne v2, v4, :cond_0

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
    iget-object p1, v3, La10/d;->n:Lz00/m;

    .line 35
    .line 36
    iput v4, p0, La10/b;->e:I

    .line 37
    .line 38
    invoke-virtual {p1, v0, p0}, Lz00/m;->b(ZLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    if-ne p0, v1, :cond_2

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_2
    :goto_0
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    check-cast p0, La10/c;

    .line 50
    .line 51
    const/4 p1, 0x5

    .line 52
    const/4 v1, 0x0

    .line 53
    invoke-static {p0, v1, v0, v1, p1}, La10/c;->a(La10/c;ZZZI)La10/c;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-virtual {v3, p0}, Lql0/j;->g(Lql0/h;)V

    .line 58
    .line 59
    .line 60
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    :goto_1
    return-object v1

    .line 63
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 64
    .line 65
    iget v1, p0, La10/b;->e:I

    .line 66
    .line 67
    const/4 v2, 0x2

    .line 68
    const/4 v3, 0x1

    .line 69
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    iget-object v5, p0, La10/b;->f:La10/d;

    .line 72
    .line 73
    if-eqz v1, :cond_5

    .line 74
    .line 75
    if-eq v1, v3, :cond_4

    .line 76
    .line 77
    if-ne v1, v2, :cond_3

    .line 78
    .line 79
    iget-boolean p0, p0, La10/b;->g:Z

    .line 80
    .line 81
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    goto :goto_3

    .line 85
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 86
    .line 87
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 88
    .line 89
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    iget-object p1, v5, La10/d;->l:Lwc0/d;

    .line 101
    .line 102
    iput v3, p0, La10/b;->e:I

    .line 103
    .line 104
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 105
    .line 106
    .line 107
    invoke-virtual {p1, p0}, Lwc0/d;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    if-ne p1, v0, :cond_6

    .line 112
    .line 113
    goto :goto_4

    .line 114
    :cond_6
    :goto_2
    check-cast p1, Ljava/lang/Boolean;

    .line 115
    .line 116
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 117
    .line 118
    .line 119
    move-result p1

    .line 120
    iget-object v1, v5, La10/d;->m:Lz00/c;

    .line 121
    .line 122
    iput-boolean p1, p0, La10/b;->g:Z

    .line 123
    .line 124
    iput v2, p0, La10/b;->e:I

    .line 125
    .line 126
    invoke-virtual {v1, v4, p0}, Lz00/c;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    if-ne p0, v0, :cond_7

    .line 131
    .line 132
    goto :goto_4

    .line 133
    :cond_7
    move v6, p1

    .line 134
    move-object p1, p0

    .line 135
    move p0, v6

    .line 136
    :goto_3
    check-cast p1, Ljava/lang/Boolean;

    .line 137
    .line 138
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 139
    .line 140
    .line 141
    move-result p1

    .line 142
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    check-cast v0, La10/c;

    .line 147
    .line 148
    const/4 v1, 0x0

    .line 149
    invoke-static {v0, v1, p1, p0, v3}, La10/c;->a(La10/c;ZZZI)La10/c;

    .line 150
    .line 151
    .line 152
    move-result-object p0

    .line 153
    invoke-virtual {v5, p0}, Lql0/j;->g(Lql0/h;)V

    .line 154
    .line 155
    .line 156
    move-object v0, v4

    .line 157
    :goto_4
    return-object v0

    .line 158
    nop

    .line 159
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
