.class public final Luf/m;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Lth/b;

.field public final f:Lxh/e;

.field public final g:Lxh/e;

.field public final h:Lxh/e;

.field public final i:Lyj/b;

.field public final j:Lxh/e;

.field public final k:Luf/c;

.field public final l:Lyy0/c2;

.field public final m:Lyy0/c2;

.field public n:Lof/j;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lth/b;Lxh/e;Lxh/e;Lxh/e;Lyj/b;Lxh/e;)V
    .locals 1

    .line 1
    const-string v0, "vin"

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
    iput-object p1, p0, Luf/m;->d:Ljava/lang/String;

    .line 10
    .line 11
    iput-object p2, p0, Luf/m;->e:Lth/b;

    .line 12
    .line 13
    iput-object p3, p0, Luf/m;->f:Lxh/e;

    .line 14
    .line 15
    iput-object p4, p0, Luf/m;->g:Lxh/e;

    .line 16
    .line 17
    iput-object p5, p0, Luf/m;->h:Lxh/e;

    .line 18
    .line 19
    iput-object p6, p0, Luf/m;->i:Lyj/b;

    .line 20
    .line 21
    iput-object p7, p0, Luf/m;->j:Lxh/e;

    .line 22
    .line 23
    sget-object p1, Luf/c;->a:Luf/c;

    .line 24
    .line 25
    iput-object p1, p0, Luf/m;->k:Luf/c;

    .line 26
    .line 27
    new-instance p1, Llc/q;

    .line 28
    .line 29
    sget-object p2, Llc/a;->c:Llc/c;

    .line 30
    .line 31
    invoke-direct {p1, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    iput-object p1, p0, Luf/m;->l:Lyy0/c2;

    .line 39
    .line 40
    iput-object p1, p0, Luf/m;->m:Lyy0/c2;

    .line 41
    .line 42
    sget-object p1, Lof/j;->e:Lof/j;

    .line 43
    .line 44
    iput-object p1, p0, Luf/m;->n:Lof/j;

    .line 45
    .line 46
    invoke-virtual {p0}, Luf/m;->b()V

    .line 47
    .line 48
    .line 49
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 6

    .line 1
    new-instance v0, Lu2/d;

    .line 2
    .line 3
    const/16 v1, 0xc

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lu2/d;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sget-object v1, Lgi/b;->e:Lgi/b;

    .line 9
    .line 10
    sget-object v2, Lgi/a;->e:Lgi/a;

    .line 11
    .line 12
    const-class v3, Luf/m;

    .line 13
    .line 14
    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    const/16 v4, 0x24

    .line 19
    .line 20
    invoke-static {v3, v4}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v4

    .line 24
    const/16 v5, 0x2e

    .line 25
    .line 26
    invoke-static {v5, v4, v4}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 31
    .line 32
    .line 33
    move-result v5

    .line 34
    if-nez v5, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const-string v3, "Kt"

    .line 38
    .line 39
    invoke-static {v4, v3}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    :goto_0
    const/4 v4, 0x0

    .line 44
    invoke-static {v3, v2, v1, v4, v0}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 45
    .line 46
    .line 47
    :cond_1
    iget-object v0, p0, Luf/m;->l:Lyy0/c2;

    .line 48
    .line 49
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    move-object v2, v1

    .line 54
    check-cast v2, Llc/q;

    .line 55
    .line 56
    new-instance v3, Lu2/d;

    .line 57
    .line 58
    const/16 v4, 0xd

    .line 59
    .line 60
    invoke-direct {v3, v4}, Lu2/d;-><init>(I)V

    .line 61
    .line 62
    .line 63
    invoke-static {v2, v3}, Llc/a;->b(Llc/q;Lay0/k;)Llc/q;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    if-eqz v0, :cond_1

    .line 72
    .line 73
    return-void
.end method

.method public final b()V
    .locals 4

    .line 1
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lrp0/a;

    .line 6
    .line 7
    const/16 v2, 0x17

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-direct {v1, p0, v3, v2}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x3

    .line 14
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 15
    .line 16
    .line 17
    return-void
.end method
