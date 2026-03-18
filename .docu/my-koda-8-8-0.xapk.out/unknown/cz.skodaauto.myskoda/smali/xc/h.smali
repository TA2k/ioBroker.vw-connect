.class public final Lxc/h;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lwc/a;

.field public final e:Lth/b;

.field public final f:Lyj/b;

.field public final g:Lyj/b;

.field public final h:Ljava/lang/String;

.field public i:Ljava/util/List;

.field public final j:Lac/f;

.field public final k:Lyy0/c2;

.field public final l:Lac/i;

.field public final m:Lyy0/l1;


# direct methods
.method public constructor <init>(Lwc/a;Lth/b;Lyj/b;Lyj/b;Ljava/lang/String;)V
    .locals 7

    .line 1
    const-string v0, "chargingCardId"

    .line 2
    .line 3
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lxc/h;->d:Lwc/a;

    .line 10
    .line 11
    iput-object p2, p0, Lxc/h;->e:Lth/b;

    .line 12
    .line 13
    iput-object p3, p0, Lxc/h;->f:Lyj/b;

    .line 14
    .line 15
    iput-object p4, p0, Lxc/h;->g:Lyj/b;

    .line 16
    .line 17
    iput-object p5, p0, Lxc/h;->h:Ljava/lang/String;

    .line 18
    .line 19
    sget-object v6, Lmx0/s;->d:Lmx0/s;

    .line 20
    .line 21
    iput-object v6, p0, Lxc/h;->i:Ljava/util/List;

    .line 22
    .line 23
    sget-object p1, Lac/f;->a:Lac/f;

    .line 24
    .line 25
    iput-object p1, p0, Lxc/h;->j:Lac/f;

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
    iput-object p1, p0, Lxc/h;->k:Lyy0/c2;

    .line 39
    .line 40
    new-instance v1, Lac/i;

    .line 41
    .line 42
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    new-instance v3, Lac/a0;

    .line 47
    .line 48
    const-string p3, ""

    .line 49
    .line 50
    invoke-direct {v3, p3, p3}, Lac/a0;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    const/4 v4, 0x0

    .line 54
    const/4 v5, 0x0

    .line 55
    invoke-direct/range {v1 .. v6}, Lac/i;-><init>(Lr7/a;Lac/a0;ZLac/e;Ljava/util/List;)V

    .line 56
    .line 57
    .line 58
    iput-object v1, p0, Lxc/h;->l:Lac/i;

    .line 59
    .line 60
    iget-object p3, v1, Lac/i;->l:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast p3, Lyy0/l1;

    .line 63
    .line 64
    new-instance p4, Lal0/y0;

    .line 65
    .line 66
    const/16 p5, 0x1a

    .line 67
    .line 68
    const/4 v0, 0x3

    .line 69
    const/4 v1, 0x0

    .line 70
    invoke-direct {p4, v0, v1, p5}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 71
    .line 72
    .line 73
    new-instance p5, Lbn0/f;

    .line 74
    .line 75
    const/4 v2, 0x5

    .line 76
    invoke-direct {p5, p1, p3, p4, v2}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 77
    .line 78
    .line 79
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    const-wide/16 p3, 0x0

    .line 84
    .line 85
    invoke-static {v0, p3, p4}, Lyy0/u1;->a(IJ)Lyy0/z1;

    .line 86
    .line 87
    .line 88
    move-result-object p3

    .line 89
    new-instance p4, Llc/q;

    .line 90
    .line 91
    invoke-direct {p4, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    invoke-static {p5, p1, p3, p4}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    iput-object p1, p0, Lxc/h;->m:Lyy0/l1;

    .line 99
    .line 100
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    new-instance p2, Lxc/g;

    .line 105
    .line 106
    const/4 p3, 0x0

    .line 107
    invoke-direct {p2, p0, v1, p3}, Lxc/g;-><init>(Lxc/h;Lkotlin/coroutines/Continuation;I)V

    .line 108
    .line 109
    .line 110
    invoke-static {p1, v1, v1, p2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 111
    .line 112
    .line 113
    return-void
.end method
