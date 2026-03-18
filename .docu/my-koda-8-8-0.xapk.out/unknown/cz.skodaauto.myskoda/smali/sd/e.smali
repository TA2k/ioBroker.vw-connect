.class public final Lsd/e;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lzb/s0;

.field public final e:Ljd/b;

.field public final f:Lsd/b;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/c2;


# direct methods
.method public constructor <init>(Lzb/s0;Ljd/b;Lrd/a;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lsd/e;->d:Lzb/s0;

    .line 5
    .line 6
    iput-object p2, p0, Lsd/e;->e:Ljd/b;

    .line 7
    .line 8
    sget-object p1, Lsd/b;->a:Lsd/b;

    .line 9
    .line 10
    iput-object p1, p0, Lsd/e;->f:Lsd/b;

    .line 11
    .line 12
    const/4 p1, 0x0

    .line 13
    invoke-static {p3, p1}, Lsd/b;->b(Lrd/a;Lpd/o0;)Lsd/d;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    iget-object v0, p3, Lrd/a;->e:Lpd/m;

    .line 18
    .line 19
    iget-object v1, v0, Lpd/m;->C:Ljava/lang/Boolean;

    .line 20
    .line 21
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 22
    .line 23
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    invoke-static {p2, v1}, Lsd/d;->a(Lsd/d;Z)Lsd/d;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 32
    .line 33
    .line 34
    move-result-object p2

    .line 35
    iput-object p2, p0, Lsd/e;->g:Lyy0/c2;

    .line 36
    .line 37
    iput-object p2, p0, Lsd/e;->h:Lyy0/c2;

    .line 38
    .line 39
    iget-object v0, v0, Lpd/m;->C:Ljava/lang/Boolean;

    .line 40
    .line 41
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    if-nez v0, :cond_0

    .line 46
    .line 47
    invoke-static {p3, p1}, Lsd/b;->b(Lrd/a;Lpd/o0;)Lsd/d;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    const/4 p3, 0x0

    .line 52
    invoke-static {p0, p3}, Lsd/d;->a(Lsd/d;Z)Lsd/d;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-virtual {p2, p1, p0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    return-void

    .line 60
    :cond_0
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 61
    .line 62
    .line 63
    move-result-object p2

    .line 64
    new-instance v0, Lny/f0;

    .line 65
    .line 66
    const/16 v1, 0x1c

    .line 67
    .line 68
    invoke-direct {v0, v1, p3, p0, p1}, Lny/f0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 69
    .line 70
    .line 71
    const/4 p0, 0x3

    .line 72
    invoke-static {p2, p1, p1, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 73
    .line 74
    .line 75
    return-void
.end method
