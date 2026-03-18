.class public final Lg1/f;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lay0/n;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lvy0/b0;


# direct methods
.method public synthetic constructor <init>(Lay0/n;Ljava/lang/Object;Lvy0/b0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p5, p0, Lg1/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lg1/f;->f:Lay0/n;

    .line 4
    .line 5
    iput-object p2, p0, Lg1/f;->g:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Lg1/f;->h:Lvy0/b0;

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 7

    .line 1
    iget p1, p0, Lg1/f;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lg1/f;

    .line 7
    .line 8
    iget-object v3, p0, Lg1/f;->h:Lvy0/b0;

    .line 9
    .line 10
    const/4 v5, 0x1

    .line 11
    iget-object v1, p0, Lg1/f;->f:Lay0/n;

    .line 12
    .line 13
    iget-object v2, p0, Lg1/f;->g:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v4, p2

    .line 16
    invoke-direct/range {v0 .. v5}, Lg1/f;-><init>(Lay0/n;Ljava/lang/Object;Lvy0/b0;Lkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    return-object v0

    .line 20
    :pswitch_0
    move-object v4, p2

    .line 21
    new-instance v1, Lg1/f;

    .line 22
    .line 23
    move-object v5, v4

    .line 24
    iget-object v4, p0, Lg1/f;->h:Lvy0/b0;

    .line 25
    .line 26
    const/4 v6, 0x0

    .line 27
    iget-object v2, p0, Lg1/f;->f:Lay0/n;

    .line 28
    .line 29
    iget-object v3, p0, Lg1/f;->g:Ljava/lang/Object;

    .line 30
    .line 31
    invoke-direct/range {v1 .. v6}, Lg1/f;-><init>(Lay0/n;Ljava/lang/Object;Lvy0/b0;Lkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    return-object v1

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lg1/f;->d:I

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
    invoke-virtual {p0, p1, p2}, Lg1/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg1/f;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lg1/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lg1/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lg1/f;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lg1/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 3

    .line 1
    iget v0, p0, Lg1/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lg1/f;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iput v2, p0, Lg1/f;->e:I

    .line 31
    .line 32
    iget-object p1, p0, Lg1/f;->f:Lay0/n;

    .line 33
    .line 34
    iget-object v1, p0, Lg1/f;->g:Ljava/lang/Object;

    .line 35
    .line 36
    invoke-interface {p1, v1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    if-ne p1, v0, :cond_2

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_2
    :goto_0
    new-instance p1, Li2/e;

    .line 44
    .line 45
    invoke-direct {p1}, Li2/e;-><init>()V

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Lg1/f;->h:Lvy0/b0;

    .line 49
    .line 50
    invoke-static {p0, p1}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 51
    .line 52
    .line 53
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    :goto_1
    return-object v0

    .line 56
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 57
    .line 58
    iget v1, p0, Lg1/f;->e:I

    .line 59
    .line 60
    const/4 v2, 0x1

    .line 61
    if-eqz v1, :cond_4

    .line 62
    .line 63
    if-ne v1, v2, :cond_3

    .line 64
    .line 65
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 70
    .line 71
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 72
    .line 73
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw p0

    .line 77
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    iput v2, p0, Lg1/f;->e:I

    .line 81
    .line 82
    iget-object p1, p0, Lg1/f;->f:Lay0/n;

    .line 83
    .line 84
    iget-object v1, p0, Lg1/f;->g:Ljava/lang/Object;

    .line 85
    .line 86
    invoke-interface {p1, v1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    if-ne p1, v0, :cond_5

    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_5
    :goto_2
    new-instance p1, Lg1/a;

    .line 94
    .line 95
    invoke-direct {p1}, Lg1/a;-><init>()V

    .line 96
    .line 97
    .line 98
    iget-object p0, p0, Lg1/f;->h:Lvy0/b0;

    .line 99
    .line 100
    invoke-static {p0, p1}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 101
    .line 102
    .line 103
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    :goto_3
    return-object v0

    .line 106
    nop

    .line 107
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
