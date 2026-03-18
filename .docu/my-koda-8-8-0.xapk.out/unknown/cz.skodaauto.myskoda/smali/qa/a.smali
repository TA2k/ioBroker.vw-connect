.class public final Lqa/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lay0/k;


# direct methods
.method public constructor <init>(Lay0/k;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lqa/a;->d:I

    .line 1
    iput-object p1, p0, Lqa/a;->f:Lay0/k;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/coroutines/Continuation;Lay0/k;I)V
    .locals 0

    .line 2
    iput p3, p0, Lqa/a;->d:I

    iput-object p2, p0, Lqa/a;->f:Lay0/k;

    const/4 p2, 0x2

    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Lqa/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lqa/a;

    .line 7
    .line 8
    iget-object p0, p0, Lqa/a;->f:Lay0/k;

    .line 9
    .line 10
    invoke-direct {v0, p0, p2}, Lqa/a;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, v0, Lqa/a;->e:Ljava/lang/Object;

    .line 14
    .line 15
    return-object v0

    .line 16
    :pswitch_0
    new-instance v0, Lqa/a;

    .line 17
    .line 18
    iget-object p0, p0, Lqa/a;->f:Lay0/k;

    .line 19
    .line 20
    const/4 v1, 0x1

    .line 21
    invoke-direct {v0, p2, p0, v1}, Lqa/a;-><init>(Lkotlin/coroutines/Continuation;Lay0/k;I)V

    .line 22
    .line 23
    .line 24
    iput-object p1, v0, Lqa/a;->e:Ljava/lang/Object;

    .line 25
    .line 26
    return-object v0

    .line 27
    :pswitch_1
    new-instance v0, Lqa/a;

    .line 28
    .line 29
    iget-object p0, p0, Lqa/a;->f:Lay0/k;

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    invoke-direct {v0, p2, p0, v1}, Lqa/a;-><init>(Lkotlin/coroutines/Continuation;Lay0/k;I)V

    .line 33
    .line 34
    .line 35
    iput-object p1, v0, Lqa/a;->e:Ljava/lang/Object;

    .line 36
    .line 37
    return-object v0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lqa/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lq6/b;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lqa/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lqa/a;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lqa/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    check-cast p1, Lna/k;

    .line 23
    .line 24
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 25
    .line 26
    invoke-virtual {p0, p1, p2}, Lqa/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Lqa/a;

    .line 31
    .line 32
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lqa/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :pswitch_1
    check-cast p1, Lna/k;

    .line 40
    .line 41
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 42
    .line 43
    invoke-virtual {p0, p1, p2}, Lqa/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    check-cast p0, Lqa/a;

    .line 48
    .line 49
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    invoke-virtual {p0, p1}, Lqa/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    nop

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lqa/a;->d:I

    .line 2
    .line 3
    const-string v1, "null cannot be cast to non-null type androidx.room.coroutines.RawConnectionAccessor"

    .line 4
    .line 5
    iget-object v2, p0, Lqa/a;->f:Lay0/k;

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
    iget-object p0, p0, Lqa/a;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Lq6/b;

    .line 18
    .line 19
    invoke-interface {v2, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 26
    .line 27
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object p0, p0, Lqa/a;->e:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Lna/k;

    .line 33
    .line 34
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    check-cast p0, Lna/b0;

    .line 38
    .line 39
    invoke-interface {p0}, Lna/b0;->d()Lua/a;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-interface {v2, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 49
    .line 50
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iget-object p0, p0, Lqa/a;->e:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast p0, Lna/k;

    .line 56
    .line 57
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    check-cast p0, Lna/b0;

    .line 61
    .line 62
    invoke-interface {p0}, Lna/b0;->d()Lua/a;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    invoke-interface {v2, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
