.class public final Lsg/p;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lkotlin/jvm/internal/k;

.field public final e:Lkotlin/jvm/internal/k;

.field public final f:Lsg/g;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/c2;


# direct methods
.method public constructor <init>(Lay0/k;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    check-cast p1, Lkotlin/jvm/internal/k;

    .line 5
    .line 6
    iput-object p1, p0, Lsg/p;->d:Lkotlin/jvm/internal/k;

    .line 7
    .line 8
    check-cast p2, Lkotlin/jvm/internal/k;

    .line 9
    .line 10
    iput-object p2, p0, Lsg/p;->e:Lkotlin/jvm/internal/k;

    .line 11
    .line 12
    sget-object p1, Lsg/g;->a:Lsg/g;

    .line 13
    .line 14
    iput-object p1, p0, Lsg/p;->f:Lsg/g;

    .line 15
    .line 16
    new-instance p1, Llc/q;

    .line 17
    .line 18
    sget-object p2, Llc/a;->c:Llc/c;

    .line 19
    .line 20
    invoke-direct {p1, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    iput-object p1, p0, Lsg/p;->g:Lyy0/c2;

    .line 28
    .line 29
    iput-object p1, p0, Lsg/p;->h:Lyy0/c2;

    .line 30
    .line 31
    invoke-virtual {p0}, Lsg/p;->a()V

    .line 32
    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 4

    .line 1
    new-instance v0, Llc/q;

    .line 2
    .line 3
    sget-object v1, Llc/a;->c:Llc/c;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lsg/p;->g:Lyy0/c2;

    .line 9
    .line 10
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    invoke-virtual {v1, v2, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    new-instance v1, Lrp0/a;

    .line 22
    .line 23
    const/16 v3, 0x9

    .line 24
    .line 25
    invoke-direct {v1, p0, v2, v3}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x3

    .line 29
    invoke-static {v0, v2, v2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public final b(Lsg/n;)V
    .locals 1

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lsg/m;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    check-cast p1, Lsg/m;

    .line 11
    .line 12
    iget-object p1, p1, Lsg/m;->a:Lsg/f;

    .line 13
    .line 14
    iget-object p0, p0, Lsg/p;->e:Lkotlin/jvm/internal/k;

    .line 15
    .line 16
    iget-object p1, p1, Lsg/f;->f:Lkg/p0;

    .line 17
    .line 18
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    sget-object v0, Lsg/l;->a:Lsg/l;

    .line 23
    .line 24
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    if-eqz p1, :cond_1

    .line 29
    .line 30
    invoke-virtual {p0}, Lsg/p;->a()V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_1
    new-instance p0, La8/r0;

    .line 35
    .line 36
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 37
    .line 38
    .line 39
    throw p0
.end method
