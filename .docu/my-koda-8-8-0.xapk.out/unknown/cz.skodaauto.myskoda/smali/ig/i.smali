.class public final Lig/i;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Lbq0/i;

.field public final f:Lif0/d0;

.field public final g:Lhz/a;

.field public final h:Lhz/a;

.field public final i:Lyy0/c2;

.field public final j:Lyy0/l1;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lbq0/i;Lif0/d0;Lhz/a;Lhz/a;)V
    .locals 8

    .line 1
    const-string v0, "evseId"

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
    iput-object p1, p0, Lig/i;->d:Ljava/lang/String;

    .line 10
    .line 11
    iput-object p2, p0, Lig/i;->e:Lbq0/i;

    .line 12
    .line 13
    iput-object p3, p0, Lig/i;->f:Lif0/d0;

    .line 14
    .line 15
    iput-object p4, p0, Lig/i;->g:Lhz/a;

    .line 16
    .line 17
    iput-object p5, p0, Lig/i;->h:Lhz/a;

    .line 18
    .line 19
    new-instance v1, Lig/f;

    .line 20
    .line 21
    new-instance v3, Lig/a;

    .line 22
    .line 23
    const-string p2, ""

    .line 24
    .line 25
    invoke-direct {v3, p2, p2}, Lig/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const/4 v6, 0x0

    .line 29
    const/4 v7, 0x0

    .line 30
    const/4 v4, 0x0

    .line 31
    const/4 v5, 0x1

    .line 32
    move-object v2, p1

    .line 33
    invoke-direct/range {v1 .. v7}, Lig/f;-><init>(Ljava/lang/String;Lig/a;Llc/l;ZZZ)V

    .line 34
    .line 35
    .line 36
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    iput-object p1, p0, Lig/i;->i:Lyy0/c2;

    .line 41
    .line 42
    new-instance p2, Lag/r;

    .line 43
    .line 44
    const/4 p3, 0x4

    .line 45
    invoke-direct {p2, p1, p3}, Lag/r;-><init>(Lyy0/c2;I)V

    .line 46
    .line 47
    .line 48
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 49
    .line 50
    .line 51
    move-result-object p3

    .line 52
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    check-cast p1, Lig/f;

    .line 57
    .line 58
    const-string p4, "<this>"

    .line 59
    .line 60
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    iget-object v1, p1, Lig/f;->a:Ljava/lang/String;

    .line 64
    .line 65
    iget-object v2, p1, Lig/f;->b:Lig/a;

    .line 66
    .line 67
    iget-object v3, p1, Lig/f;->c:Llc/l;

    .line 68
    .line 69
    iget-boolean v5, p1, Lig/f;->e:Z

    .line 70
    .line 71
    iget-boolean v6, p1, Lig/f;->f:Z

    .line 72
    .line 73
    iget-boolean v4, p1, Lig/f;->d:Z

    .line 74
    .line 75
    new-instance v0, Lig/e;

    .line 76
    .line 77
    invoke-direct/range {v0 .. v6}, Lig/e;-><init>(Ljava/lang/String;Lig/a;Llc/l;ZZZ)V

    .line 78
    .line 79
    .line 80
    sget-object p1, Lyy0/u1;->a:Lyy0/w1;

    .line 81
    .line 82
    invoke-static {p2, p3, p1, v0}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    iput-object p1, p0, Lig/i;->j:Lyy0/l1;

    .line 87
    .line 88
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 6

    .line 1
    :cond_0
    iget-object v0, p0, Lig/i;->i:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    move-object v2, v1

    .line 8
    check-cast v2, Lig/f;

    .line 9
    .line 10
    const/4 v3, 0x1

    .line 11
    const/16 v4, 0x2b

    .line 12
    .line 13
    const/4 v5, 0x0

    .line 14
    invoke-static {v2, v5, v5, v3, v4}, Lig/f;->a(Lig/f;Lig/a;Llc/l;ZI)Lig/f;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    new-instance v1, Lig/g;

    .line 29
    .line 30
    const/4 v2, 0x0

    .line 31
    invoke-direct {v1, p0, v5, v2}, Lig/g;-><init>(Lig/i;Lkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    const/4 p0, 0x3

    .line 35
    invoke-static {v0, v5, v5, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 36
    .line 37
    .line 38
    return-void
.end method
