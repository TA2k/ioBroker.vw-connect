.class public final Lz40/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public synthetic d:Lxj0/b;

.field public synthetic e:Lbl0/h;


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lbl0/i0;

    .line 2
    .line 3
    check-cast p2, Lxj0/b;

    .line 4
    .line 5
    check-cast p3, Lbl0/h;

    .line 6
    .line 7
    check-cast p4, Lkotlin/coroutines/Continuation;

    .line 8
    .line 9
    new-instance p0, Lz40/a;

    .line 10
    .line 11
    const/4 p1, 0x4

    .line 12
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    iput-object p2, p0, Lz40/a;->d:Lxj0/b;

    .line 16
    .line 17
    iput-object p3, p0, Lz40/a;->e:Lbl0/h;

    .line 18
    .line 19
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lz40/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lz40/a;->d:Lxj0/b;

    .line 2
    .line 3
    iget-object p0, p0, Lz40/a;->e:Lbl0/h;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    new-instance p1, Llx0/l;

    .line 11
    .line 12
    invoke-direct {p1, v0, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-object p1
.end method
