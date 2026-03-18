.class public final Ljh/j;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ljh/l;


# direct methods
.method public synthetic constructor <init>(Ljh/l;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ljh/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ljh/j;->f:Ljh/l;

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
    .locals 1

    .line 1
    iget p1, p0, Ljh/j;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ljh/j;

    .line 7
    .line 8
    iget-object p0, p0, Ljh/j;->f:Ljh/l;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ljh/j;-><init>(Ljh/l;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ljh/j;

    .line 16
    .line 17
    iget-object p0, p0, Ljh/j;->f:Ljh/l;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ljh/j;-><init>(Ljh/l;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ljh/j;->d:I

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
    invoke-virtual {p0, p1, p2}, Ljh/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ljh/j;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ljh/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ljh/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ljh/j;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ljh/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Ljh/j;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    .line 6
    .line 7
    iget-object v3, p0, Ljh/j;->f:Ljh/l;

    .line 8
    .line 9
    const/4 v4, 0x1

    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 14
    .line 15
    iget v5, p0, Ljh/j;->e:I

    .line 16
    .line 17
    if-eqz v5, :cond_1

    .line 18
    .line 19
    if-ne v5, v4, :cond_0

    .line 20
    .line 21
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    new-instance p1, Lzb/f0;

    .line 35
    .line 36
    iget v2, v3, Ljh/l;->h:I

    .line 37
    .line 38
    sget v5, Lmy0/c;->g:I

    .line 39
    .line 40
    const-wide/16 v5, 0x5

    .line 41
    .line 42
    sget-object v7, Lmy0/e;->h:Lmy0/e;

    .line 43
    .line 44
    invoke-static {v5, v6, v7}, Lmy0/h;->t(JLmy0/e;)J

    .line 45
    .line 46
    .line 47
    move-result-wide v5

    .line 48
    invoke-direct {p1, v2, v5, v6}, Lzb/f0;-><init>(IJ)V

    .line 49
    .line 50
    .line 51
    iget-object v2, v3, Ljh/l;->d:Lai/e;

    .line 52
    .line 53
    new-instance v5, Li40/e1;

    .line 54
    .line 55
    const/16 v6, 0xd

    .line 56
    .line 57
    invoke-direct {v5, v3, v6}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 58
    .line 59
    .line 60
    iput v4, p0, Ljh/j;->e:I

    .line 61
    .line 62
    invoke-static {p1, v2, v5, p0}, Lzb/b;->z(Lzb/f0;Lai/e;Li40/e1;Lrx0/c;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    if-ne p0, v0, :cond_2

    .line 67
    .line 68
    move-object v1, v0

    .line 69
    :cond_2
    :goto_0
    return-object v1

    .line 70
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 71
    .line 72
    iget v5, p0, Ljh/j;->e:I

    .line 73
    .line 74
    if-eqz v5, :cond_4

    .line 75
    .line 76
    if-ne v5, v4, :cond_3

    .line 77
    .line 78
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 83
    .line 84
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    throw p0

    .line 88
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    iget-object p1, v3, Ljh/l;->i:Lyy0/c2;

    .line 92
    .line 93
    new-instance v2, Ljh/i;

    .line 94
    .line 95
    const/4 v5, 0x0

    .line 96
    invoke-direct {v2, v3, v5}, Ljh/i;-><init>(Ljh/l;I)V

    .line 97
    .line 98
    .line 99
    new-instance v5, Ljh/i;

    .line 100
    .line 101
    invoke-direct {v5, v3, v4}, Ljh/i;-><init>(Ljh/l;I)V

    .line 102
    .line 103
    .line 104
    iput v4, p0, Ljh/j;->e:I

    .line 105
    .line 106
    invoke-static {p1, v2, v5, p0}, Lzb/b;->x(Lyy0/i1;Lay0/a;Lay0/a;Lrx0/i;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    if-ne p0, v0, :cond_5

    .line 111
    .line 112
    move-object v1, v0

    .line 113
    :cond_5
    :goto_1
    return-object v1

    .line 114
    nop

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
