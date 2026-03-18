.class public final Lna/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lna/b;


# instance fields
.field public final d:Lua/b;

.field public final e:Ljava/lang/String;

.field public final f:Lkotlin/jvm/internal/k;

.field public final g:Llx0/q;


# direct methods
.method public constructor <init>(Lua/b;Ljava/lang/String;Lay0/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lna/q;->d:Lua/b;

    .line 5
    .line 6
    iput-object p2, p0, Lna/q;->e:Ljava/lang/String;

    .line 7
    .line 8
    check-cast p3, Lkotlin/jvm/internal/k;

    .line 9
    .line 10
    iput-object p3, p0, Lna/q;->f:Lkotlin/jvm/internal/k;

    .line 11
    .line 12
    new-instance p1, Lmc/e;

    .line 13
    .line 14
    const/16 p2, 0xa

    .line 15
    .line 16
    invoke-direct {p1, p0, p2}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 17
    .line 18
    .line 19
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    iput-object p1, p0, Lna/q;->g:Llx0/q;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final close()V
    .locals 1

    .line 1
    iget-object p0, p0, Lna/q;->g:Llx0/q;

    .line 2
    .line 3
    invoke-virtual {p0}, Llx0/q;->isInitialized()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lua/a;

    .line 14
    .line 15
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public final u(ZLay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-interface {p3}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    sget-object v0, Lna/p;->e:Let/d;

    .line 6
    .line 7
    invoke-interface {p1, v0}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    check-cast p1, Lna/p;

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    if-eqz p1, :cond_0

    .line 15
    .line 16
    iget-object p1, p1, Lna/p;->d:Lna/o;

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move-object p1, v0

    .line 20
    :goto_0
    if-eqz p1, :cond_1

    .line 21
    .line 22
    invoke-interface {p2, p1, p3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :cond_1
    new-instance p1, Lna/o;

    .line 28
    .line 29
    iget-object v1, p0, Lna/q;->g:Llx0/q;

    .line 30
    .line 31
    invoke-virtual {v1}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    check-cast v1, Lua/a;

    .line 36
    .line 37
    iget-object p0, p0, Lna/q;->f:Lkotlin/jvm/internal/k;

    .line 38
    .line 39
    invoke-direct {p1, p0, v1}, Lna/o;-><init>(Lay0/n;Lua/a;)V

    .line 40
    .line 41
    .line 42
    new-instance p0, Lna/p;

    .line 43
    .line 44
    invoke-direct {p0, p1}, Lna/p;-><init>(Lna/o;)V

    .line 45
    .line 46
    .line 47
    new-instance v1, Lna/e;

    .line 48
    .line 49
    invoke-direct {v1, p2, p1, v0}, Lna/e;-><init>(Lay0/n;Lna/o;Lkotlin/coroutines/Continuation;)V

    .line 50
    .line 51
    .line 52
    invoke-static {p0, v1, p3}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method
