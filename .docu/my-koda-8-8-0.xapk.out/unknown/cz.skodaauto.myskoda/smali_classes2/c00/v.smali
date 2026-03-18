.class public final Lc00/v;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lc00/i0;


# direct methods
.method public synthetic constructor <init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p1, p0, Lc00/v;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lc00/v;->f:Lc00/i0;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Lc00/v;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lc00/v;

    .line 7
    .line 8
    iget-object p0, p0, Lc00/v;->f:Lc00/i0;

    .line 9
    .line 10
    const/4 v1, 0x5

    .line 11
    invoke-direct {v0, v1, p0, p2}, Lc00/v;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lc00/v;->e:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lc00/v;

    .line 18
    .line 19
    iget-object p0, p0, Lc00/v;->f:Lc00/i0;

    .line 20
    .line 21
    const/4 v1, 0x4

    .line 22
    invoke-direct {v0, v1, p0, p2}, Lc00/v;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lc00/v;->e:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Lc00/v;

    .line 29
    .line 30
    iget-object p0, p0, Lc00/v;->f:Lc00/i0;

    .line 31
    .line 32
    const/4 v1, 0x3

    .line 33
    invoke-direct {v0, v1, p0, p2}, Lc00/v;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 34
    .line 35
    .line 36
    iput-object p1, v0, Lc00/v;->e:Ljava/lang/Object;

    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_2
    new-instance v0, Lc00/v;

    .line 40
    .line 41
    iget-object p0, p0, Lc00/v;->f:Lc00/i0;

    .line 42
    .line 43
    const/4 v1, 0x2

    .line 44
    invoke-direct {v0, v1, p0, p2}, Lc00/v;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 45
    .line 46
    .line 47
    iput-object p1, v0, Lc00/v;->e:Ljava/lang/Object;

    .line 48
    .line 49
    return-object v0

    .line 50
    :pswitch_3
    new-instance v0, Lc00/v;

    .line 51
    .line 52
    iget-object p0, p0, Lc00/v;->f:Lc00/i0;

    .line 53
    .line 54
    const/4 v1, 0x1

    .line 55
    invoke-direct {v0, v1, p0, p2}, Lc00/v;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 56
    .line 57
    .line 58
    iput-object p1, v0, Lc00/v;->e:Ljava/lang/Object;

    .line 59
    .line 60
    return-object v0

    .line 61
    :pswitch_4
    new-instance v0, Lc00/v;

    .line 62
    .line 63
    iget-object p0, p0, Lc00/v;->f:Lc00/i0;

    .line 64
    .line 65
    const/4 v1, 0x0

    .line 66
    invoke-direct {v0, v1, p0, p2}, Lc00/v;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 67
    .line 68
    .line 69
    iput-object p1, v0, Lc00/v;->e:Ljava/lang/Object;

    .line 70
    .line 71
    return-object v0

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lc00/v;->d:I

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
    invoke-virtual {p0, p1, p2}, Lc00/v;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc00/v;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc00/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    check-cast p1, Lvy0/b0;

    .line 23
    .line 24
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 25
    .line 26
    invoke-virtual {p0, p1, p2}, Lc00/v;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Lc00/v;

    .line 31
    .line 32
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lc00/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :pswitch_1
    check-cast p1, Lne0/c;

    .line 40
    .line 41
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 42
    .line 43
    invoke-virtual {p0, p1, p2}, Lc00/v;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    check-cast p0, Lc00/v;

    .line 48
    .line 49
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    invoke-virtual {p0, p1}, Lc00/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    return-object p1

    .line 55
    :pswitch_2
    check-cast p1, Lvy0/b0;

    .line 56
    .line 57
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 58
    .line 59
    invoke-virtual {p0, p1, p2}, Lc00/v;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    check-cast p0, Lc00/v;

    .line 64
    .line 65
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    invoke-virtual {p0, p1}, Lc00/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    return-object p1

    .line 71
    :pswitch_3
    check-cast p1, Lss0/b;

    .line 72
    .line 73
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 74
    .line 75
    invoke-virtual {p0, p1, p2}, Lc00/v;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Lc00/v;

    .line 80
    .line 81
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Lc00/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    return-object p1

    .line 87
    :pswitch_4
    check-cast p1, Lss0/b;

    .line 88
    .line 89
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 90
    .line 91
    invoke-virtual {p0, p1, p2}, Lc00/v;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    check-cast p0, Lc00/v;

    .line 96
    .line 97
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 98
    .line 99
    invoke-virtual {p0, p1}, Lc00/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    return-object p1

    .line 103
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lc00/v;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x3

    .line 5
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v4, p0, Lc00/v;->f:Lc00/i0;

    .line 8
    .line 9
    iget-object p0, p0, Lc00/v;->e:Ljava/lang/Object;

    .line 10
    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    check-cast p0, Lne0/c;

    .line 15
    .line 16
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v4, p0}, Lc00/i0;->j(Lne0/c;)V

    .line 22
    .line 23
    .line 24
    return-object v3

    .line 25
    :pswitch_0
    check-cast p0, Lvy0/b0;

    .line 26
    .line 27
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    new-instance p1, Lc00/x;

    .line 33
    .line 34
    const/4 v0, 0x2

    .line 35
    invoke-direct {p1, v0, v4, v1}, Lc00/x;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 36
    .line 37
    .line 38
    invoke-static {p0, v1, v1, p1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 39
    .line 40
    .line 41
    new-instance p1, Lc00/x;

    .line 42
    .line 43
    invoke-direct {p1, v2, v4, v1}, Lc00/x;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 44
    .line 45
    .line 46
    invoke-static {p0, v1, v1, p1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0

    .line 51
    :pswitch_1
    check-cast p0, Lne0/c;

    .line 52
    .line 53
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 54
    .line 55
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v4, p0}, Lc00/i0;->j(Lne0/c;)V

    .line 59
    .line 60
    .line 61
    return-object v3

    .line 62
    :pswitch_2
    check-cast p0, Lvy0/b0;

    .line 63
    .line 64
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 65
    .line 66
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    new-instance p1, Lc00/x;

    .line 70
    .line 71
    const/4 v0, 0x0

    .line 72
    invoke-direct {p1, v0, v4, v1}, Lc00/x;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 73
    .line 74
    .line 75
    invoke-static {p0, v1, v1, p1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 76
    .line 77
    .line 78
    new-instance p1, Lc00/x;

    .line 79
    .line 80
    const/4 v0, 0x1

    .line 81
    invoke-direct {p1, v0, v4, v1}, Lc00/x;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 82
    .line 83
    .line 84
    invoke-static {p0, v1, v1, p1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 85
    .line 86
    .line 87
    return-object v3

    .line 88
    :pswitch_3
    check-cast p0, Lss0/b;

    .line 89
    .line 90
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 91
    .line 92
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    iget-object p1, v4, Lc00/i0;->j:Lij0/a;

    .line 96
    .line 97
    invoke-static {p0, p1}, Ljp/dc;->a(Lss0/b;Lij0/a;)Lc00/d0;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    invoke-virtual {v4, p0}, Lql0/j;->g(Lql0/h;)V

    .line 102
    .line 103
    .line 104
    return-object v3

    .line 105
    :pswitch_4
    check-cast p0, Lss0/b;

    .line 106
    .line 107
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 108
    .line 109
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    iget-object p1, v4, Lc00/i0;->j:Lij0/a;

    .line 113
    .line 114
    invoke-static {p0, p1}, Ljp/dc;->a(Lss0/b;Lij0/a;)Lc00/d0;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    invoke-virtual {v4, p0}, Lql0/j;->g(Lql0/h;)V

    .line 119
    .line 120
    .line 121
    return-object v3

    .line 122
    nop

    .line 123
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
