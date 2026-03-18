.class public abstract Lql0/j;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lyy0/c2;

.field public final e:Lyy0/c2;

.field public final f:Lpw0/a;

.field public final g:Lyy0/l1;


# direct methods
.method public constructor <init>(Lql0/h;)V
    .locals 3

    .line 1
    const-string v0, "initialState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 7
    .line 8
    .line 9
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    iput-object p1, p0, Lql0/j;->d:Lyy0/c2;

    .line 14
    .line 15
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 16
    .line 17
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iput-object v0, p0, Lql0/j;->e:Lyy0/c2;

    .line 22
    .line 23
    invoke-static {}, Lvy0/e0;->e()Lpw0/a;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    iget-object v1, v1, Lr7/a;->d:Lpx0/g;

    .line 32
    .line 33
    sget-object v2, Lvy0/h1;->d:Lvy0/h1;

    .line 34
    .line 35
    invoke-interface {v1, v2}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    check-cast v1, Lvy0/i1;

    .line 40
    .line 41
    new-instance v2, Lvy0/z1;

    .line 42
    .line 43
    invoke-direct {v2, v1}, Lvy0/k1;-><init>(Lvy0/i1;)V

    .line 44
    .line 45
    .line 46
    invoke-static {v0, v2}, Lvy0/e0;->H(Lvy0/b0;Lpx0/e;)Lpw0/a;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    iput-object v0, p0, Lql0/j;->f:Lpw0/a;

    .line 51
    .line 52
    new-instance v0, Lyy0/l1;

    .line 53
    .line 54
    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 55
    .line 56
    .line 57
    iput-object v0, p0, Lql0/j;->g:Lyy0/l1;

    .line 58
    .line 59
    return-void
.end method


# virtual methods
.method public final a()Lql0/h;
    .locals 0

    .line 1
    iget-object p0, p0, Lql0/j;->d:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lql0/h;

    .line 8
    .line 9
    return-object p0
.end method

.method public final b(Lay0/n;)V
    .locals 3

    .line 1
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lna/e;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-direct {v1, p0, p1, v2}, Lna/e;-><init>(Lql0/j;Lay0/n;Lkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    const/4 p0, 0x3

    .line 12
    invoke-static {v0, v2, v2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final d()V
    .locals 3

    .line 1
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 2
    .line 3
    iget-object v1, p0, Lql0/j;->e:Lyy0/c2;

    .line 4
    .line 5
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    invoke-virtual {v1, v2, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lql0/j;->f:Lpw0/a;

    .line 13
    .line 14
    iget-object p0, p0, Lpw0/a;->e:Lpx0/g;

    .line 15
    .line 16
    invoke-static {p0}, Lvy0/e0;->n(Lpx0/g;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public f()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lql0/j;->d()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final g(Lql0/h;)V
    .locals 1

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lql0/j;->d:Lyy0/c2;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    return-void
.end method
