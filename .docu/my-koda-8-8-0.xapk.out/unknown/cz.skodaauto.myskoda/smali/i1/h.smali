.class public final Li1/h;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Li1/l;

.field public final synthetic g:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Li1/l;Ll2/b1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Li1/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li1/h;->f:Li1/l;

    .line 4
    .line 5
    iput-object p2, p0, Li1/h;->g:Ll2/b1;

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
    .locals 2

    .line 1
    iget p1, p0, Li1/h;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Li1/h;

    .line 7
    .line 8
    iget-object v0, p0, Li1/h;->g:Ll2/b1;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Li1/h;->f:Li1/l;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Li1/h;-><init>(Li1/l;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Li1/h;

    .line 18
    .line 19
    iget-object v0, p0, Li1/h;->g:Ll2/b1;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Li1/h;->f:Li1/l;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Li1/h;-><init>(Li1/l;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Li1/h;->d:I

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
    invoke-virtual {p0, p1, p2}, Li1/h;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Li1/h;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Li1/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Li1/h;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Li1/h;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Li1/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 6

    .line 1
    iget v0, p0, Li1/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Li1/h;->e:I

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
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    new-instance p1, Ljava/util/ArrayList;

    .line 33
    .line 34
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 35
    .line 36
    .line 37
    iget-object v1, p0, Li1/h;->f:Li1/l;

    .line 38
    .line 39
    iget-object v1, v1, Li1/l;->a:Lyy0/q1;

    .line 40
    .line 41
    new-instance v3, Li1/g;

    .line 42
    .line 43
    iget-object v4, p0, Li1/h;->g:Ll2/b1;

    .line 44
    .line 45
    const/4 v5, 0x1

    .line 46
    invoke-direct {v3, p1, v4, v5}, Li1/g;-><init>(Ljava/util/ArrayList;Ll2/b1;I)V

    .line 47
    .line 48
    .line 49
    iput v2, p0, Li1/h;->e:I

    .line 50
    .line 51
    invoke-virtual {v1, v3, p0}, Lyy0/q1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    :goto_0
    return-object v0

    .line 55
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 56
    .line 57
    iget v1, p0, Li1/h;->e:I

    .line 58
    .line 59
    const/4 v2, 0x1

    .line 60
    if-eqz v1, :cond_3

    .line 61
    .line 62
    if-ne v1, v2, :cond_2

    .line 63
    .line 64
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_2
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
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    new-instance p1, Ljava/util/ArrayList;

    .line 82
    .line 83
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 84
    .line 85
    .line 86
    iget-object v1, p0, Li1/h;->f:Li1/l;

    .line 87
    .line 88
    iget-object v1, v1, Li1/l;->a:Lyy0/q1;

    .line 89
    .line 90
    new-instance v3, Li1/g;

    .line 91
    .line 92
    iget-object v4, p0, Li1/h;->g:Ll2/b1;

    .line 93
    .line 94
    const/4 v5, 0x0

    .line 95
    invoke-direct {v3, p1, v4, v5}, Li1/g;-><init>(Ljava/util/ArrayList;Ll2/b1;I)V

    .line 96
    .line 97
    .line 98
    iput v2, p0, Li1/h;->e:I

    .line 99
    .line 100
    invoke-virtual {v1, v3, p0}, Lyy0/q1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    :goto_1
    return-object v0

    .line 104
    nop

    .line 105
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
