.class public final Lrm0/c;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lqm0/b;

.field public final i:I

.field public final j:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lqm0/b;ILjava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "onboardingKey"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lrm0/b;

    .line 7
    .line 8
    const/16 v1, 0xf

    .line 9
    .line 10
    invoke-direct {v0, v1}, Lrm0/b;-><init>(I)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lrm0/c;->h:Lqm0/b;

    .line 17
    .line 18
    iput p2, p0, Lrm0/c;->i:I

    .line 19
    .line 20
    iput-object p3, p0, Lrm0/c;->j:Ljava/lang/String;

    .line 21
    .line 22
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    new-instance p2, Lny/f0;

    .line 27
    .line 28
    const/16 p3, 0x14

    .line 29
    .line 30
    const/4 v0, 0x0

    .line 31
    invoke-direct {p2, p0, v0, p3}, Lny/f0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    const/4 p0, 0x3

    .line 35
    invoke-static {p1, v0, v0, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 36
    .line 37
    .line 38
    return-void
.end method


# virtual methods
.method public final h(I)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lrm0/b;

    .line 6
    .line 7
    iget-object v0, v0, Lrm0/b;->b:Lrm0/a;

    .line 8
    .line 9
    sget-object v1, Lrm0/a;->d:Lrm0/a;

    .line 10
    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    iget v0, p0, Lrm0/c;->i:I

    .line 15
    .line 16
    add-int/lit8 v0, v0, -0x2

    .line 17
    .line 18
    if-ne p1, v0, :cond_1

    .line 19
    .line 20
    sget-object v0, Lrm0/a;->f:Lrm0/a;

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    sget-object v0, Lrm0/a;->e:Lrm0/a;

    .line 24
    .line 25
    :goto_0
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    check-cast v1, Lrm0/b;

    .line 30
    .line 31
    const/4 v2, 0x0

    .line 32
    const/4 v3, 0x5

    .line 33
    invoke-static {v1, v2, v0, p1, v3}, Lrm0/b;->a(Lrm0/b;ZLrm0/a;II)Lrm0/b;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 38
    .line 39
    .line 40
    return-void
.end method
