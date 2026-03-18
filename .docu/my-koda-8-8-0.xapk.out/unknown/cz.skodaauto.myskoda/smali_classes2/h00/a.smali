.class public final Lh00/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh00/c;


# direct methods
.method public synthetic constructor <init>(Lh00/c;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh00/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh00/a;->e:Lh00/c;

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
    iget p1, p0, Lh00/a;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lh00/a;

    .line 7
    .line 8
    iget-object p0, p0, Lh00/a;->e:Lh00/c;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lh00/a;-><init>(Lh00/c;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lh00/a;

    .line 16
    .line 17
    iget-object p0, p0, Lh00/a;->e:Lh00/c;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lh00/a;-><init>(Lh00/c;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lh00/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lyy0/j;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lh00/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh00/a;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh00/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lh00/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Lh00/a;

    .line 31
    .line 32
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lh00/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    return-object p1

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lh00/a;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object p0, p0, Lh00/a;->e:Lh00/c;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    move-object v2, p1

    .line 20
    check-cast v2, Lh00/b;

    .line 21
    .line 22
    const/4 v7, 0x0

    .line 23
    const/16 v8, 0x17

    .line 24
    .line 25
    const/4 v3, 0x0

    .line 26
    const/4 v4, 0x0

    .line 27
    const/4 v5, 0x0

    .line 28
    const/4 v6, 0x1

    .line 29
    invoke-static/range {v2 .. v8}, Lh00/b;->a(Lh00/b;Lhp0/e;Ljava/lang/String;Ljava/lang/String;ZLql0/g;I)Lh00/b;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 34
    .line 35
    .line 36
    return-object v1

    .line 37
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 38
    .line 39
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    iget-object p1, p0, Lh00/c;->l:Lug0/a;

    .line 43
    .line 44
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    check-cast p1, Lne0/t;

    .line 49
    .line 50
    if-eqz p1, :cond_0

    .line 51
    .line 52
    iget-object p1, p0, Lh00/c;->j:Lgn0/a;

    .line 53
    .line 54
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    check-cast p1, Lyy0/i;

    .line 59
    .line 60
    new-instance v0, Lh00/a;

    .line 61
    .line 62
    const/4 v2, 0x1

    .line 63
    const/4 v3, 0x0

    .line 64
    invoke-direct {v0, p0, v3, v2}, Lh00/a;-><init>(Lh00/c;Lkotlin/coroutines/Continuation;I)V

    .line 65
    .line 66
    .line 67
    new-instance v2, Lne0/n;

    .line 68
    .line 69
    invoke-direct {v2, v0, p1}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 70
    .line 71
    .line 72
    invoke-static {v2}, Lbb/j0;->d(Lyy0/i;)Lne0/n;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    new-instance v0, Lbv0/d;

    .line 77
    .line 78
    const/4 v2, 0x6

    .line 79
    invoke-direct {v0, p0, v3, v2}, Lbv0/d;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 80
    .line 81
    .line 82
    new-instance v2, Lyy0/x;

    .line 83
    .line 84
    invoke-direct {v2, p1, v0}, Lyy0/x;-><init>(Lyy0/i;Lay0/o;)V

    .line 85
    .line 86
    .line 87
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    invoke-static {v2, p1}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 92
    .line 93
    .line 94
    iget-object p0, p0, Lh00/c;->m:Lug0/c;

    .line 95
    .line 96
    invoke-virtual {p0, v3}, Lug0/c;->a(Lne0/t;)V

    .line 97
    .line 98
    .line 99
    :cond_0
    return-object v1

    .line 100
    nop

    .line 101
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
