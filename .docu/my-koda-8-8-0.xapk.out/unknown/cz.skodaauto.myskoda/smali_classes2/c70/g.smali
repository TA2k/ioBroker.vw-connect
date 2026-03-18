.class public final Lc70/g;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lc70/i;


# direct methods
.method public synthetic constructor <init>(Lc70/i;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lc70/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc70/g;->f:Lc70/i;

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
    iget v0, p0, Lc70/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lc70/g;

    .line 7
    .line 8
    iget-object p0, p0, Lc70/g;->f:Lc70/i;

    .line 9
    .line 10
    const/4 v1, 0x3

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lc70/g;-><init>(Lc70/i;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lc70/g;->e:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lc70/g;

    .line 18
    .line 19
    iget-object p0, p0, Lc70/g;->f:Lc70/i;

    .line 20
    .line 21
    const/4 v1, 0x2

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lc70/g;-><init>(Lc70/i;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lc70/g;->e:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Lc70/g;

    .line 29
    .line 30
    iget-object p0, p0, Lc70/g;->f:Lc70/i;

    .line 31
    .line 32
    const/4 v1, 0x1

    .line 33
    invoke-direct {v0, p0, p2, v1}, Lc70/g;-><init>(Lc70/i;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    iput-object p1, v0, Lc70/g;->e:Ljava/lang/Object;

    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_2
    new-instance v0, Lc70/g;

    .line 40
    .line 41
    iget-object p0, p0, Lc70/g;->f:Lc70/i;

    .line 42
    .line 43
    const/4 v1, 0x0

    .line 44
    invoke-direct {v0, p0, p2, v1}, Lc70/g;-><init>(Lc70/i;Lkotlin/coroutines/Continuation;I)V

    .line 45
    .line 46
    .line 47
    iput-object p1, v0, Lc70/g;->e:Ljava/lang/Object;

    .line 48
    .line 49
    return-object v0

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lc70/g;->d:I

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
    invoke-virtual {p0, p1, p2}, Lc70/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc70/g;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc70/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    check-cast p1, Ljava/time/OffsetDateTime;

    .line 23
    .line 24
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 25
    .line 26
    invoke-virtual {p0, p1, p2}, Lc70/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Lc70/g;

    .line 31
    .line 32
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lc70/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    return-object p1

    .line 38
    :pswitch_1
    check-cast p1, Lss0/b;

    .line 39
    .line 40
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 41
    .line 42
    invoke-virtual {p0, p1, p2}, Lc70/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    check-cast p0, Lc70/g;

    .line 47
    .line 48
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    invoke-virtual {p0, p1}, Lc70/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    return-object p1

    .line 54
    :pswitch_2
    check-cast p1, Lss0/b;

    .line 55
    .line 56
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 57
    .line 58
    invoke-virtual {p0, p1, p2}, Lc70/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    check-cast p0, Lc70/g;

    .line 63
    .line 64
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    invoke-virtual {p0, p1}, Lc70/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    return-object p1

    .line 70
    nop

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lc70/g;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v3, v0, Lc70/g;->f:Lc70/i;

    .line 8
    .line 9
    iget-object v0, v0, Lc70/g;->e:Ljava/lang/Object;

    .line 10
    .line 11
    packed-switch v1, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    check-cast v0, Lne0/c;

    .line 15
    .line 16
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v3, v0}, Lc70/i;->h(Lne0/c;)V

    .line 22
    .line 23
    .line 24
    return-object v2

    .line 25
    :pswitch_0
    move-object v14, v0

    .line 26
    check-cast v14, Ljava/time/OffsetDateTime;

    .line 27
    .line 28
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 29
    .line 30
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    move-object v4, v0

    .line 38
    check-cast v4, Lc70/h;

    .line 39
    .line 40
    const/4 v13, 0x0

    .line 41
    const/16 v15, 0x3ff

    .line 42
    .line 43
    const/4 v5, 0x0

    .line 44
    const/4 v6, 0x0

    .line 45
    const/4 v7, 0x0

    .line 46
    const/4 v8, 0x0

    .line 47
    const/4 v9, 0x0

    .line 48
    const/4 v10, 0x0

    .line 49
    const/4 v11, 0x0

    .line 50
    const/4 v12, 0x0

    .line 51
    invoke-static/range {v4 .. v15}, Lc70/h;->a(Lc70/h;Ler0/g;Llf0/i;ZLjava/lang/String;Ljava/lang/Integer;Lb70/c;Llp/mb;Lqr0/s;ZLjava/time/OffsetDateTime;I)Lc70/h;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 56
    .line 57
    .line 58
    return-object v2

    .line 59
    :pswitch_1
    check-cast v0, Lss0/b;

    .line 60
    .line 61
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 62
    .line 63
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    check-cast v1, Lc70/h;

    .line 71
    .line 72
    iget-object v4, v3, Lc70/i;->q:Lij0/a;

    .line 73
    .line 74
    invoke-static {v1, v0, v4}, Ljp/fd;->c(Lc70/h;Lss0/b;Lij0/a;)Lc70/h;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 79
    .line 80
    .line 81
    return-object v2

    .line 82
    :pswitch_2
    check-cast v0, Lss0/b;

    .line 83
    .line 84
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 85
    .line 86
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    check-cast v1, Lc70/h;

    .line 94
    .line 95
    iget-object v4, v3, Lc70/i;->q:Lij0/a;

    .line 96
    .line 97
    invoke-static {v1, v0, v4}, Ljp/fd;->c(Lc70/h;Lss0/b;Lij0/a;)Lc70/h;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 102
    .line 103
    .line 104
    return-object v2

    .line 105
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
