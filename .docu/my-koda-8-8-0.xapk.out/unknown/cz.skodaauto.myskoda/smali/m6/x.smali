.class public final Lm6/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lyy0/c2;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    sget-object v0, Lm6/a1;->b:Lm6/a1;

    .line 3
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v0

    iput-object v0, p0, Lm6/x;->a:Lyy0/c2;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lvy0/b0;)V
    .locals 12

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    sget-object v0, Ly51/d;->a:Ly51/d;

    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v0

    iput-object v0, p0, Lm6/x;->a:Lyy0/c2;

    .line 6
    const-string v0, "connectivity"

    invoke-virtual {p1, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    const-string v1, "null cannot be cast to non-null type android.net.ConnectivityManager"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v9, v0

    check-cast v9, Landroid/net/ConnectivityManager;

    const/16 v0, 0xc

    const/16 v1, 0x10

    .line 7
    filled-new-array {v0, v1}, [I

    move-result-object v8

    .line 8
    new-instance v6, Lvh/j;

    const/4 v7, 0x4

    sget-object v10, Ly51/c;->a:Ly51/c;

    const/4 v11, 0x0

    invoke-direct/range {v6 .. v11}, Lvh/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    invoke-static {v6}, Lyy0/u;->h(Lay0/n;)Lyy0/c;

    move-result-object v2

    const/4 v0, 0x4

    .line 9
    filled-new-array {v0}, [I

    move-result-object v8

    .line 10
    new-instance v6, Lvh/j;

    invoke-direct/range {v6 .. v11}, Lvh/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    invoke-static {v6}, Lyy0/u;->h(Lay0/n;)Lyy0/c;

    move-result-object v4

    const/16 v0, 0x11

    .line 11
    filled-new-array {v0}, [I

    move-result-object v8

    .line 12
    new-instance v6, Lvh/j;

    sget-object v10, Ly51/b;->a:Ly51/b;

    invoke-direct/range {v6 .. v11}, Lvh/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    invoke-static {v6}, Lyy0/u;->h(Lay0/n;)Lyy0/c;

    move-result-object v3

    .line 13
    new-instance v1, Lvh/j;

    const/4 v6, 0x0

    const/4 v7, 0x5

    move-object v5, p0

    invoke-direct/range {v1 .. v7}, Lvh/j;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    const/4 v0, 0x3

    invoke-static {p2, v11, v11, v1, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    return-void
.end method


# virtual methods
.method public a()Lm6/z0;
    .locals 0

    .line 1
    iget-object p0, p0, Lm6/x;->a:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lm6/z0;

    .line 8
    .line 9
    return-object p0
.end method

.method public b(Lm6/z0;)V
    .locals 5

    .line 1
    const-string v0, "newState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :cond_0
    iget-object v0, p0, Lm6/x;->a:Lyy0/c2;

    .line 7
    .line 8
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    move-object v2, v1

    .line 13
    check-cast v2, Lm6/z0;

    .line 14
    .line 15
    instance-of v3, v2, Lm6/s0;

    .line 16
    .line 17
    if-eqz v3, :cond_1

    .line 18
    .line 19
    const/4 v3, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_1
    sget-object v3, Lm6/a1;->b:Lm6/a1;

    .line 22
    .line 23
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    :goto_0
    if-eqz v3, :cond_2

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_2
    instance-of v3, v2, Lm6/d;

    .line 31
    .line 32
    if-eqz v3, :cond_3

    .line 33
    .line 34
    iget v3, p1, Lm6/z0;->a:I

    .line 35
    .line 36
    iget v4, v2, Lm6/z0;->a:I

    .line 37
    .line 38
    if-le v3, v4, :cond_4

    .line 39
    .line 40
    :goto_1
    move-object v2, p1

    .line 41
    goto :goto_2

    .line 42
    :cond_3
    instance-of v3, v2, Lm6/h0;

    .line 43
    .line 44
    if-eqz v3, :cond_5

    .line 45
    .line 46
    :cond_4
    :goto_2
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    if-eqz v0, :cond_0

    .line 51
    .line 52
    return-void

    .line 53
    :cond_5
    new-instance p0, La8/r0;

    .line 54
    .line 55
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 56
    .line 57
    .line 58
    throw p0
.end method
