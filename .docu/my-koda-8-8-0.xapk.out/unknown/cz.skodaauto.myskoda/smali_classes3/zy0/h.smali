.class public final Lzy0/h;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lzy0/j;

.field public final synthetic h:Lyy0/j;


# direct methods
.method public constructor <init>(Lzy0/j;Lyy0/j;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lzy0/h;->d:I

    .line 1
    iput-object p1, p0, Lzy0/h;->g:Lzy0/j;

    iput-object p2, p0, Lzy0/h;->h:Lyy0/j;

    iput-object p3, p0, Lzy0/h;->f:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lzy0/j;Lyy0/j;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lzy0/h;->d:I

    .line 2
    iput-object p1, p0, Lzy0/h;->g:Lzy0/j;

    iput-object p2, p0, Lzy0/h;->h:Lyy0/j;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Lzy0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lzy0/h;

    .line 7
    .line 8
    iget-object v1, p0, Lzy0/h;->g:Lzy0/j;

    .line 9
    .line 10
    iget-object p0, p0, Lzy0/h;->h:Lyy0/j;

    .line 11
    .line 12
    invoke-direct {v0, v1, p0, p2}, Lzy0/h;-><init>(Lzy0/j;Lyy0/j;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, v0, Lzy0/h;->f:Ljava/lang/Object;

    .line 16
    .line 17
    return-object v0

    .line 18
    :pswitch_0
    new-instance p1, Lzy0/h;

    .line 19
    .line 20
    iget-object v0, p0, Lzy0/h;->h:Lyy0/j;

    .line 21
    .line 22
    iget-object v1, p0, Lzy0/h;->f:Ljava/lang/Object;

    .line 23
    .line 24
    iget-object p0, p0, Lzy0/h;->g:Lzy0/j;

    .line 25
    .line 26
    invoke-direct {p1, p0, v0, v1, p2}, Lzy0/h;-><init>(Lzy0/j;Lyy0/j;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    return-object p1

    .line 30
    nop

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lzy0/h;->d:I

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
    invoke-virtual {p0, p1, p2}, Lzy0/h;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lzy0/h;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lzy0/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lzy0/h;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lzy0/h;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lzy0/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 9

    .line 1
    iget v0, p0, Lzy0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lzy0/h;->e:I

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
    iget-object p1, p0, Lzy0/h;->f:Ljava/lang/Object;

    .line 31
    .line 32
    move-object v5, p1

    .line 33
    check-cast v5, Lvy0/b0;

    .line 34
    .line 35
    new-instance v4, Lkotlin/jvm/internal/f0;

    .line 36
    .line 37
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 38
    .line 39
    .line 40
    iget-object v6, p0, Lzy0/h;->g:Lzy0/j;

    .line 41
    .line 42
    iget-object p1, v6, Lzy0/f;->g:Lyy0/i;

    .line 43
    .line 44
    new-instance v3, Le1/b0;

    .line 45
    .line 46
    iget-object v7, p0, Lzy0/h;->h:Lyy0/j;

    .line 47
    .line 48
    const/4 v8, 0x6

    .line 49
    invoke-direct/range {v3 .. v8}, Le1/b0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 50
    .line 51
    .line 52
    iput v2, p0, Lzy0/h;->e:I

    .line 53
    .line 54
    invoke-interface {p1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    if-ne p0, v0, :cond_2

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 62
    .line 63
    :goto_1
    return-object v0

    .line 64
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 65
    .line 66
    iget v1, p0, Lzy0/h;->e:I

    .line 67
    .line 68
    const/4 v2, 0x1

    .line 69
    if-eqz v1, :cond_4

    .line 70
    .line 71
    if-ne v1, v2, :cond_3

    .line 72
    .line 73
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 78
    .line 79
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 80
    .line 81
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    throw p0

    .line 85
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    iget-object p1, p0, Lzy0/h;->g:Lzy0/j;

    .line 89
    .line 90
    iget-object p1, p1, Lzy0/j;->h:Lrx0/i;

    .line 91
    .line 92
    iget-object v1, p0, Lzy0/h;->f:Ljava/lang/Object;

    .line 93
    .line 94
    iput v2, p0, Lzy0/h;->e:I

    .line 95
    .line 96
    iget-object v2, p0, Lzy0/h;->h:Lyy0/j;

    .line 97
    .line 98
    invoke-interface {p1, v2, v1, p0}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    if-ne p0, v0, :cond_5

    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 106
    .line 107
    :goto_3
    return-object v0

    .line 108
    nop

    .line 109
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
