.class public final Lno0/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lno0/c;

.field public final synthetic f:Lkr0/c;


# direct methods
.method public synthetic constructor <init>(Lno0/c;Lkr0/c;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lno0/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lno0/b;->e:Lno0/c;

    .line 4
    .line 5
    iput-object p2, p0, Lno0/b;->f:Lkr0/c;

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
    iget p1, p0, Lno0/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lno0/b;

    .line 7
    .line 8
    iget-object v0, p0, Lno0/b;->f:Lkr0/c;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lno0/b;->e:Lno0/c;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lno0/b;-><init>(Lno0/c;Lkr0/c;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lno0/b;

    .line 18
    .line 19
    iget-object v0, p0, Lno0/b;->f:Lkr0/c;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lno0/b;->e:Lno0/c;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lno0/b;-><init>(Lno0/c;Lkr0/c;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lno0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 7
    .line 8
    invoke-virtual {p0, p1, p2}, Lno0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lno0/b;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lno0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    return-object p1

    .line 20
    :pswitch_0
    check-cast p1, Lyy0/j;

    .line 21
    .line 22
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 23
    .line 24
    invoke-virtual {p0, p1, p2}, Lno0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    check-cast p0, Lno0/b;

    .line 29
    .line 30
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Lno0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    return-object p1

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lno0/b;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object v2, p0, Lno0/b;->f:Lkr0/c;

    .line 6
    .line 7
    iget-object p0, p0, Lno0/b;->e:Lno0/c;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lno0/c;->d:Ljr0/c;

    .line 18
    .line 19
    invoke-static {v2}, Lnm0/b;->j(Lkr0/c;)Lkr0/b;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-virtual {p0, p1}, Ljr0/c;->a(Lkr0/b;)V

    .line 24
    .line 25
    .line 26
    return-object v1

    .line 27
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lno0/c;->c:Ljr0/f;

    .line 33
    .line 34
    invoke-virtual {p0, v2}, Ljr0/f;->a(Lkr0/c;)V

    .line 35
    .line 36
    .line 37
    return-object v1

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
