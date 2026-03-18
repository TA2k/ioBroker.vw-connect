.class public final Lc00/k;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lc00/p;


# direct methods
.method public synthetic constructor <init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lc00/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc00/k;->f:Lc00/p;

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
    iget v0, p0, Lc00/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lc00/k;

    .line 7
    .line 8
    iget-object p0, p0, Lc00/k;->f:Lc00/p;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lc00/k;-><init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lc00/k;->e:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lc00/k;

    .line 18
    .line 19
    iget-object p0, p0, Lc00/k;->f:Lc00/p;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lc00/k;-><init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lc00/k;->e:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

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
    iget v0, p0, Lc00/k;->d:I

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
    invoke-virtual {p0, p1, p2}, Lc00/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc00/k;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc00/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lc00/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, Lc00/k;

    .line 27
    .line 28
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Lc00/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lc00/k;->d:I

    .line 2
    .line 3
    iget-object v1, p0, Lc00/k;->f:Lc00/p;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x3

    .line 7
    iget-object p0, p0, Lc00/k;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Lvy0/b0;

    .line 10
    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    new-instance p1, Lc00/j;

    .line 20
    .line 21
    const/4 v0, 0x2

    .line 22
    invoke-direct {p1, v1, v2, v0}, Lc00/j;-><init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    invoke-static {p0, v2, v2, p1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 26
    .line 27
    .line 28
    new-instance p1, Lc00/j;

    .line 29
    .line 30
    invoke-direct {p1, v1, v2, v3}, Lc00/j;-><init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    invoke-static {p0, v2, v2, p1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 34
    .line 35
    .line 36
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    new-instance p1, Lc00/j;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-direct {p1, v1, v2, v0}, Lc00/j;-><init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    invoke-static {p0, v2, v2, p1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 51
    .line 52
    .line 53
    new-instance p1, Lc00/j;

    .line 54
    .line 55
    const/4 v0, 0x1

    .line 56
    invoke-direct {p1, v1, v2, v0}, Lc00/j;-><init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V

    .line 57
    .line 58
    .line 59
    invoke-static {p0, v2, v2, p1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0

    .line 64
    nop

    .line 65
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
