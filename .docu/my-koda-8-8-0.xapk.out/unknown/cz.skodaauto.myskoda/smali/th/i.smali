.class public final Lth/i;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lt10/k;

.field public final e:Lth/b;

.field public final f:Lid/a;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/l1;


# direct methods
.method public constructor <init>(Lt10/k;Lth/b;Lid/a;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lth/i;->d:Lt10/k;

    .line 5
    .line 6
    iput-object p2, p0, Lth/i;->e:Lth/b;

    .line 7
    .line 8
    iput-object p3, p0, Lth/i;->f:Lid/a;

    .line 9
    .line 10
    new-instance p1, Lth/j;

    .line 11
    .line 12
    sget-object p2, Lmx0/s;->d:Lmx0/s;

    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-direct {p1, p2, v0, v1, v1}, Lth/j;-><init>(Ljava/util/List;ZLbh/c;Llc/l;)V

    .line 17
    .line 18
    .line 19
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    iput-object p1, p0, Lth/i;->g:Lyy0/c2;

    .line 24
    .line 25
    new-instance p2, Llb0/y;

    .line 26
    .line 27
    const/16 v0, 0xc

    .line 28
    .line 29
    invoke-direct {p2, v0, p1, p0}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    check-cast p1, Lth/j;

    .line 41
    .line 42
    invoke-static {p1, p3}, Lkp/ba;->c(Lth/j;Lid/a;)Lth/g;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    sget-object p3, Lyy0/u1;->a:Lyy0/w1;

    .line 47
    .line 48
    invoke-static {p2, v0, p3, p1}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    iput-object p1, p0, Lth/i;->h:Lyy0/l1;

    .line 53
    .line 54
    return-void
.end method


# virtual methods
.method public final a(Lth/f;)V
    .locals 7

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lth/c;->a:Lth/c;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const/4 v1, 0x3

    .line 13
    const/4 v2, 0x0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    new-instance v0, Lrp0/a;

    .line 21
    .line 22
    const/16 v3, 0xf

    .line 23
    .line 24
    invoke-direct {v0, p0, v2, v3}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    invoke-static {p1, v2, v2, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :cond_0
    sget-object v0, Lth/e;->a:Lth/e;

    .line 32
    .line 33
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_2

    .line 38
    .line 39
    const-string p1, "<this>"

    .line 40
    .line 41
    iget-object v0, p0, Lth/i;->g:Lyy0/c2;

    .line 42
    .line 43
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    :cond_1
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    move-object v1, p0

    .line 51
    check-cast v1, Lth/j;

    .line 52
    .line 53
    const/4 v5, 0x0

    .line 54
    const/4 v6, 0x1

    .line 55
    const/4 v2, 0x0

    .line 56
    const/4 v3, 0x0

    .line 57
    const/4 v4, 0x0

    .line 58
    invoke-static/range {v1 .. v6}, Lth/j;->a(Lth/j;Ljava/util/List;ZLbh/c;Llc/l;I)Lth/j;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    invoke-virtual {v0, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    if-eqz p0, :cond_1

    .line 67
    .line 68
    return-void

    .line 69
    :cond_2
    instance-of v0, p1, Lth/d;

    .line 70
    .line 71
    if-eqz v0, :cond_3

    .line 72
    .line 73
    check-cast p1, Lth/d;

    .line 74
    .line 75
    iget p1, p1, Lth/d;->a:I

    .line 76
    .line 77
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    new-instance v3, La7/y0;

    .line 82
    .line 83
    const/16 v4, 0x8

    .line 84
    .line 85
    invoke-direct {v3, p0, p1, v2, v4}, La7/y0;-><init>(Ljava/lang/Object;ILkotlin/coroutines/Continuation;I)V

    .line 86
    .line 87
    .line 88
    invoke-static {v0, v2, v2, v3, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 89
    .line 90
    .line 91
    return-void

    .line 92
    :cond_3
    new-instance p0, La8/r0;

    .line 93
    .line 94
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 95
    .line 96
    .line 97
    throw p0
.end method
