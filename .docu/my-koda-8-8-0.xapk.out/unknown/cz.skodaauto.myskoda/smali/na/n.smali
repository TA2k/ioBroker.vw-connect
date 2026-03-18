.class public final Lna/n;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lna/o;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lay0/k;


# direct methods
.method public constructor <init>(Lna/o;Ljava/lang/String;Lay0/k;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lna/n;->d:Lna/o;

    .line 2
    .line 3
    iput-object p2, p0, Lna/n;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p3, p0, Lna/n;->f:Lay0/k;

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    new-instance v0, Lna/n;

    .line 2
    .line 3
    iget-object v1, p0, Lna/n;->e:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lna/n;->f:Lay0/k;

    .line 6
    .line 7
    iget-object p0, p0, Lna/n;->d:Lna/o;

    .line 8
    .line 9
    invoke-direct {v0, p0, v1, v2, p1}, Lna/n;-><init>(Lna/o;Ljava/lang/String;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lna/n;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lna/n;

    .line 8
    .line 9
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lna/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lna/n;->d:Lna/o;

    .line 7
    .line 8
    iget-object p1, p1, Lna/o;->b:Lua/a;

    .line 9
    .line 10
    iget-object v0, p0, Lna/n;->e:Ljava/lang/String;

    .line 11
    .line 12
    invoke-interface {p1, v0}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iget-object p0, p0, Lna/n;->f:Lay0/k;

    .line 17
    .line 18
    :try_start_0
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    const/4 v0, 0x0

    .line 23
    invoke-static {p1, v0}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 24
    .line 25
    .line 26
    return-object p0

    .line 27
    :catchall_0
    move-exception p0

    .line 28
    :try_start_1
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 29
    :catchall_1
    move-exception v0

    .line 30
    invoke-static {p1, p0}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 31
    .line 32
    .line 33
    throw v0
.end method
