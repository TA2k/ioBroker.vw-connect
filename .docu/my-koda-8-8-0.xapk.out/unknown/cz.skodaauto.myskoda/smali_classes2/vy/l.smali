.class public final Lvy/l;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lvy/v;

.field public final synthetic g:Lvy0/b0;


# direct methods
.method public synthetic constructor <init>(Lvy/v;Lvy0/b0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lvy/l;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lvy/l;->f:Lvy/v;

    .line 4
    .line 5
    iput-object p2, p0, Lvy/l;->g:Lvy0/b0;

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
    iget v0, p0, Lvy/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lvy/l;

    .line 7
    .line 8
    iget-object v1, p0, Lvy/l;->g:Lvy0/b0;

    .line 9
    .line 10
    const/4 v2, 0x2

    .line 11
    iget-object p0, p0, Lvy/l;->f:Lvy/v;

    .line 12
    .line 13
    invoke-direct {v0, p0, v1, p2, v2}, Lvy/l;-><init>(Lvy/v;Lvy0/b0;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Lvy/l;->e:Ljava/lang/Object;

    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_0
    new-instance v0, Lvy/l;

    .line 20
    .line 21
    iget-object v1, p0, Lvy/l;->g:Lvy0/b0;

    .line 22
    .line 23
    const/4 v2, 0x1

    .line 24
    iget-object p0, p0, Lvy/l;->f:Lvy/v;

    .line 25
    .line 26
    invoke-direct {v0, p0, v1, p2, v2}, Lvy/l;-><init>(Lvy/v;Lvy0/b0;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    iput-object p1, v0, Lvy/l;->e:Ljava/lang/Object;

    .line 30
    .line 31
    return-object v0

    .line 32
    :pswitch_1
    new-instance v0, Lvy/l;

    .line 33
    .line 34
    iget-object v1, p0, Lvy/l;->g:Lvy0/b0;

    .line 35
    .line 36
    const/4 v2, 0x0

    .line 37
    iget-object p0, p0, Lvy/l;->f:Lvy/v;

    .line 38
    .line 39
    invoke-direct {v0, p0, v1, p2, v2}, Lvy/l;-><init>(Lvy/v;Lvy0/b0;Lkotlin/coroutines/Continuation;I)V

    .line 40
    .line 41
    .line 42
    iput-object p1, v0, Lvy/l;->e:Ljava/lang/Object;

    .line 43
    .line 44
    return-object v0

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lvy/l;->d:I

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
    invoke-virtual {p0, p1, p2}, Lvy/l;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lvy/l;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lvy/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    check-cast p1, Lne0/c;

    .line 23
    .line 24
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 25
    .line 26
    invoke-virtual {p0, p1, p2}, Lvy/l;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Lvy/l;

    .line 31
    .line 32
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lvy/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lvy/l;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    check-cast p0, Lvy/l;

    .line 47
    .line 48
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    invoke-virtual {p0, p1}, Lvy/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    return-object p1

    .line 54
    nop

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lvy/l;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    iget-object v3, p0, Lvy/l;->g:Lvy0/b0;

    .line 7
    .line 8
    iget-object v4, p0, Lvy/l;->f:Lvy/v;

    .line 9
    .line 10
    iget-object p0, p0, Lvy/l;->e:Ljava/lang/Object;

    .line 11
    .line 12
    packed-switch v0, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    check-cast p0, Lne0/c;

    .line 16
    .line 17
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 18
    .line 19
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    invoke-static {v4, v3, p0, v2}, Lvy/v;->h(Lvy/v;Lvy0/b0;Lne0/s;Lcn0/c;)V

    .line 23
    .line 24
    .line 25
    return-object v1

    .line 26
    :pswitch_0
    check-cast p0, Lne0/c;

    .line 27
    .line 28
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 29
    .line 30
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    invoke-static {v4, v3, p0, v2}, Lvy/v;->h(Lvy/v;Lvy0/b0;Lne0/s;Lcn0/c;)V

    .line 34
    .line 35
    .line 36
    return-object v1

    .line 37
    :pswitch_1
    check-cast p0, Lss0/b;

    .line 38
    .line 39
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    sget-object p1, Lss0/e;->g0:Lss0/e;

    .line 45
    .line 46
    invoke-static {p0, p1}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 47
    .line 48
    .line 49
    move-result v11

    .line 50
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    move-object v5, p0

    .line 55
    check-cast v5, Lvy/p;

    .line 56
    .line 57
    const/4 v10, 0x0

    .line 58
    const/16 v12, 0xff

    .line 59
    .line 60
    const/4 v6, 0x0

    .line 61
    const/4 v7, 0x0

    .line 62
    const/4 v8, 0x0

    .line 63
    const/4 v9, 0x0

    .line 64
    invoke-static/range {v5 .. v12}, Lvy/p;->a(Lvy/p;ZZLvy/o;Lbo0/l;Lvy/n;ZI)Lvy/p;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-virtual {v4, p0}, Lql0/j;->g(Lql0/h;)V

    .line 69
    .line 70
    .line 71
    new-instance p0, Lvy/k;

    .line 72
    .line 73
    const/4 p1, 0x0

    .line 74
    invoke-direct {p0, p1, v2, v4}, Lvy/k;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 75
    .line 76
    .line 77
    const/4 p1, 0x3

    .line 78
    invoke-static {v3, v2, v2, p0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 79
    .line 80
    .line 81
    new-instance p0, Lvy/k;

    .line 82
    .line 83
    const/4 v0, 0x1

    .line 84
    invoke-direct {p0, v0, v2, v4}, Lvy/k;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 85
    .line 86
    .line 87
    invoke-static {v3, v2, v2, p0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 88
    .line 89
    .line 90
    return-object v1

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
