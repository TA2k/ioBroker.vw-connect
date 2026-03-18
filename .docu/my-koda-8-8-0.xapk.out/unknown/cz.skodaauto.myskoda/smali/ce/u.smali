.class public final Lce/u;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Lag/c;

.field public final f:Lyy0/c2;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/c2;

.field public final i:Lyy0/l1;

.field public final j:Lyy0/l1;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lag/c;)V
    .locals 7

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lce/u;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lce/u;->e:Lag/c;

    .line 7
    .line 8
    const/4 p1, 0x0

    .line 9
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 10
    .line 11
    .line 12
    move-result-object p2

    .line 13
    iput-object p2, p0, Lce/u;->f:Lyy0/c2;

    .line 14
    .line 15
    iput-object p2, p0, Lce/u;->g:Lyy0/c2;

    .line 16
    .line 17
    new-instance p2, Lce/v;

    .line 18
    .line 19
    new-instance v0, Llc/q;

    .line 20
    .line 21
    sget-object v1, Llc/a;->c:Llc/c;

    .line 22
    .line 23
    invoke-direct {v0, v1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    invoke-direct {p2, p1, v0, v2, v2}, Lce/v;-><init>(Lae/f;Llc/q;ZZ)V

    .line 28
    .line 29
    .line 30
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 31
    .line 32
    .line 33
    move-result-object p2

    .line 34
    iput-object p2, p0, Lce/u;->h:Lyy0/c2;

    .line 35
    .line 36
    new-instance v0, Lag/r;

    .line 37
    .line 38
    const/4 v2, 0x2

    .line 39
    invoke-direct {v0, p2, v2}, Lag/r;-><init>(Lyy0/c2;I)V

    .line 40
    .line 41
    .line 42
    new-instance p2, La10/a;

    .line 43
    .line 44
    const/4 v2, 0x7

    .line 45
    invoke-direct {p2, p0, p1, v2}, La10/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 46
    .line 47
    .line 48
    new-instance p1, Lne0/n;

    .line 49
    .line 50
    invoke-direct {p1, p2, v0}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 51
    .line 52
    .line 53
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    const/4 v0, 0x3

    .line 58
    const-wide/16 v2, 0x0

    .line 59
    .line 60
    invoke-static {v0, v2, v3}, Lyy0/u1;->a(IJ)Lyy0/z1;

    .line 61
    .line 62
    .line 63
    move-result-object v4

    .line 64
    new-instance v5, Llc/q;

    .line 65
    .line 66
    invoke-direct {v5, v1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    invoke-static {p1, p2, v4, v5}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    new-instance p2, Lce/s;

    .line 74
    .line 75
    const/4 v4, 0x0

    .line 76
    invoke-direct {p2, p1, v4}, Lce/s;-><init>(Lyy0/l1;I)V

    .line 77
    .line 78
    .line 79
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 80
    .line 81
    .line 82
    move-result-object v4

    .line 83
    invoke-static {v0, v2, v3}, Lyy0/u1;->a(IJ)Lyy0/z1;

    .line 84
    .line 85
    .line 86
    move-result-object v5

    .line 87
    new-instance v6, Llc/q;

    .line 88
    .line 89
    invoke-direct {v6, v1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    invoke-static {p2, v4, v5, v6}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 93
    .line 94
    .line 95
    move-result-object p2

    .line 96
    iput-object p2, p0, Lce/u;->i:Lyy0/l1;

    .line 97
    .line 98
    new-instance p2, Lce/s;

    .line 99
    .line 100
    const/4 v4, 0x1

    .line 101
    invoke-direct {p2, p1, v4}, Lce/s;-><init>(Lyy0/l1;I)V

    .line 102
    .line 103
    .line 104
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    invoke-static {v0, v2, v3}, Lyy0/u1;->a(IJ)Lyy0/z1;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    new-instance v2, Llc/q;

    .line 113
    .line 114
    invoke-direct {v2, v1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    invoke-static {p2, p1, v0, v2}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    iput-object p1, p0, Lce/u;->j:Lyy0/l1;

    .line 122
    .line 123
    return-void
.end method
