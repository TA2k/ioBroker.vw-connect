.class public final Llh/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ldh/u;

.field public final synthetic h:Ldi/b;


# direct methods
.method public synthetic constructor <init>(Ldh/u;Ldi/b;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Llh/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Llh/b;->g:Ldh/u;

    .line 4
    .line 5
    iput-object p2, p0, Llh/b;->h:Ldi/b;

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
    iget v0, p0, Llh/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Llh/b;

    .line 7
    .line 8
    iget-object v1, p0, Llh/b;->h:Ldi/b;

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object p0, p0, Llh/b;->g:Ldh/u;

    .line 12
    .line 13
    invoke-direct {v0, p0, v1, p2, v2}, Llh/b;-><init>(Ldh/u;Ldi/b;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Llh/b;->f:Ljava/lang/Object;

    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_0
    new-instance v0, Llh/b;

    .line 20
    .line 21
    iget-object v1, p0, Llh/b;->h:Ldi/b;

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    iget-object p0, p0, Llh/b;->g:Ldh/u;

    .line 25
    .line 26
    invoke-direct {v0, p0, v1, p2, v2}, Llh/b;-><init>(Ldh/u;Ldi/b;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    iput-object p1, v0, Llh/b;->f:Ljava/lang/Object;

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
    iget v0, p0, Llh/b;->d:I

    .line 2
    .line 3
    check-cast p1, Lzg/f0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Llh/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Llh/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Llh/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Llh/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Llh/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Llh/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 4

    .line 1
    iget v0, p0, Llh/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Llh/b;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lzg/f0;

    .line 9
    .line 10
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v2, p0, Llh/b;->e:I

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
    check-cast p1, Llx0/o;

    .line 23
    .line 24
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    iget-object p1, p0, Llh/b;->h:Ldi/b;

    .line 39
    .line 40
    iget-object p1, p1, Ldi/b;->a:Ljava/lang/String;

    .line 41
    .line 42
    const/4 v2, 0x0

    .line 43
    iput-object v2, p0, Llh/b;->f:Ljava/lang/Object;

    .line 44
    .line 45
    iput v3, p0, Llh/b;->e:I

    .line 46
    .line 47
    iget-object v2, p0, Llh/b;->g:Ldh/u;

    .line 48
    .line 49
    invoke-virtual {v2, p1, v0, p0}, Ldh/u;->u(Ljava/lang/String;Lzg/f0;Lrx0/c;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    if-ne p0, v1, :cond_2

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_2
    :goto_0
    new-instance v1, Llx0/o;

    .line 57
    .line 58
    invoke-direct {v1, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    :goto_1
    return-object v1

    .line 62
    :pswitch_0
    iget-object v0, p0, Llh/b;->f:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v0, Lzg/f0;

    .line 65
    .line 66
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 67
    .line 68
    iget v2, p0, Llh/b;->e:I

    .line 69
    .line 70
    const/4 v3, 0x1

    .line 71
    if-eqz v2, :cond_4

    .line 72
    .line 73
    if-ne v2, v3, :cond_3

    .line 74
    .line 75
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    check-cast p1, Llx0/o;

    .line 79
    .line 80
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 84
    .line 85
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 86
    .line 87
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    throw p0

    .line 91
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    iget-object p1, p0, Llh/b;->h:Ldi/b;

    .line 95
    .line 96
    iget-object p1, p1, Ldi/b;->a:Ljava/lang/String;

    .line 97
    .line 98
    const/4 v2, 0x0

    .line 99
    iput-object v2, p0, Llh/b;->f:Ljava/lang/Object;

    .line 100
    .line 101
    iput v3, p0, Llh/b;->e:I

    .line 102
    .line 103
    iget-object v2, p0, Llh/b;->g:Ldh/u;

    .line 104
    .line 105
    invoke-virtual {v2, p1, v0, p0}, Ldh/u;->u(Ljava/lang/String;Lzg/f0;Lrx0/c;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    if-ne p0, v1, :cond_5

    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_5
    :goto_2
    new-instance v1, Llx0/o;

    .line 113
    .line 114
    invoke-direct {v1, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    :goto_3
    return-object v1

    .line 118
    nop

    .line 119
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
