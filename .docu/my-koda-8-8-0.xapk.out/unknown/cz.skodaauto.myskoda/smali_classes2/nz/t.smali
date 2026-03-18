.class public final Lnz/t;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lnz/z;

.field public final synthetic g:Lmz/f;


# direct methods
.method public constructor <init>(Lmz/f;Lnz/z;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lnz/t;->d:I

    .line 1
    iput-object p1, p0, Lnz/t;->g:Lmz/f;

    iput-object p2, p0, Lnz/t;->f:Lnz/z;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lnz/z;Lmz/f;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lnz/t;->d:I

    .line 2
    iput-object p1, p0, Lnz/t;->f:Lnz/z;

    iput-object p2, p0, Lnz/t;->g:Lmz/f;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p1, p0, Lnz/t;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lnz/t;

    .line 7
    .line 8
    iget-object v0, p0, Lnz/t;->f:Lnz/z;

    .line 9
    .line 10
    iget-object p0, p0, Lnz/t;->g:Lmz/f;

    .line 11
    .line 12
    invoke-direct {p1, v0, p0, p2}, Lnz/t;-><init>(Lnz/z;Lmz/f;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-object p1

    .line 16
    :pswitch_0
    new-instance p1, Lnz/t;

    .line 17
    .line 18
    iget-object v0, p0, Lnz/t;->g:Lmz/f;

    .line 19
    .line 20
    iget-object p0, p0, Lnz/t;->f:Lnz/z;

    .line 21
    .line 22
    invoke-direct {p1, v0, p0, p2}, Lnz/t;-><init>(Lmz/f;Lnz/z;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    return-object p1

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lnz/t;->d:I

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
    invoke-virtual {p0, p1, p2}, Lnz/t;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lnz/t;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lnz/t;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lnz/t;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lnz/t;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lnz/t;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 8

    .line 1
    iget v0, p0, Lnz/t;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object v2, p0, Lnz/t;->g:Lmz/f;

    .line 6
    .line 7
    iget-object v3, p0, Lnz/t;->f:Lnz/z;

    .line 8
    .line 9
    const-string v4, "call to \'resume\' before \'invoke\' with coroutine"

    .line 10
    .line 11
    const/4 v5, 0x1

    .line 12
    packed-switch v0, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 16
    .line 17
    iget v6, p0, Lnz/t;->e:I

    .line 18
    .line 19
    if-eqz v6, :cond_1

    .line 20
    .line 21
    if-ne v6, v5, :cond_0

    .line 22
    .line 23
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iput v5, p0, Lnz/t;->e:I

    .line 37
    .line 38
    sget p1, Lnz/z;->B:I

    .line 39
    .line 40
    invoke-virtual {v3, v2, p0}, Lnz/z;->k(Lmz/f;Lrx0/c;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    if-ne p0, v0, :cond_2

    .line 45
    .line 46
    move-object v1, v0

    .line 47
    :cond_2
    :goto_0
    return-object v1

    .line 48
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 49
    .line 50
    iget v6, p0, Lnz/t;->e:I

    .line 51
    .line 52
    if-eqz v6, :cond_4

    .line 53
    .line 54
    if-ne v6, v5, :cond_3

    .line 55
    .line 56
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 61
    .line 62
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw p0

    .line 66
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iget-object p1, v2, Lmz/f;->b:Lmz/e;

    .line 70
    .line 71
    invoke-static {p1}, Ljp/n1;->c(Lmz/e;)Z

    .line 72
    .line 73
    .line 74
    move-result p1

    .line 75
    if-eqz p1, :cond_5

    .line 76
    .line 77
    iget-object p1, v3, Lql0/j;->g:Lyy0/l1;

    .line 78
    .line 79
    iget-object p1, p1, Lyy0/l1;->d:Lyy0/a2;

    .line 80
    .line 81
    invoke-interface {p1}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    check-cast p1, Lnz/s;

    .line 86
    .line 87
    iget-object p1, p1, Lnz/s;->v:Lmz/a;

    .line 88
    .line 89
    sget-object v4, Lmz/a;->f:Lmz/a;

    .line 90
    .line 91
    if-ne p1, v4, :cond_6

    .line 92
    .line 93
    iget-object p1, v2, Lmz/f;->e:Lqr0/q;

    .line 94
    .line 95
    if-nez p1, :cond_6

    .line 96
    .line 97
    :cond_5
    iget-object p1, v3, Lnz/z;->n:Lrq0/f;

    .line 98
    .line 99
    new-instance v2, Lsq0/c;

    .line 100
    .line 101
    iget-object v3, v3, Lnz/z;->i:Lij0/a;

    .line 102
    .line 103
    const/4 v4, 0x0

    .line 104
    new-array v6, v4, [Ljava/lang/Object;

    .line 105
    .line 106
    check-cast v3, Ljj0/f;

    .line 107
    .line 108
    const v7, 0x7f1200ea

    .line 109
    .line 110
    .line 111
    invoke-virtual {v3, v7, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v3

    .line 115
    const/4 v6, 0x6

    .line 116
    const/4 v7, 0x0

    .line 117
    invoke-direct {v2, v6, v3, v7, v7}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    iput v5, p0, Lnz/t;->e:I

    .line 121
    .line 122
    invoke-virtual {p1, v2, v4, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    if-ne p0, v0, :cond_6

    .line 127
    .line 128
    move-object v1, v0

    .line 129
    :cond_6
    :goto_1
    return-object v1

    .line 130
    nop

    .line 131
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
