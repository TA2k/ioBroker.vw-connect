.class public final Lh40/k;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lf40/m4;

.field public final j:Lf40/p4;

.field public final k:Lrq0/f;

.field public final l:Lij0/a;

.field public final m:Lf40/y2;

.field public final n:Lf40/q1;

.field public final o:Lbq0/b;

.field public final p:Lf40/z2;

.field public final q:Lrq0/d;

.field public final r:Lf40/b3;


# direct methods
.method public constructor <init>(Lf40/j0;Ltr0/b;Lf40/m4;Lf40/p4;Lrq0/f;Lij0/a;Lf40/b0;Lf40/y2;Lf40/q1;Lbq0/b;Lf40/z2;Lrq0/d;Lf40/b3;)V
    .locals 4

    .line 1
    new-instance v0, Lh40/f;

    .line 2
    .line 3
    const/16 v1, 0xf

    .line 4
    .line 5
    and-int/lit8 v1, v1, 0x1

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const-string v2, ""

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    invoke-direct {v0, v1, v3, v2, v3}, Lh40/f;-><init>(Lh40/m;ZLjava/lang/String;Z)V

    .line 12
    .line 13
    .line 14
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 15
    .line 16
    .line 17
    iput-object p2, p0, Lh40/k;->h:Ltr0/b;

    .line 18
    .line 19
    iput-object p3, p0, Lh40/k;->i:Lf40/m4;

    .line 20
    .line 21
    iput-object p4, p0, Lh40/k;->j:Lf40/p4;

    .line 22
    .line 23
    iput-object p5, p0, Lh40/k;->k:Lrq0/f;

    .line 24
    .line 25
    iput-object p6, p0, Lh40/k;->l:Lij0/a;

    .line 26
    .line 27
    iput-object p8, p0, Lh40/k;->m:Lf40/y2;

    .line 28
    .line 29
    iput-object p9, p0, Lh40/k;->n:Lf40/q1;

    .line 30
    .line 31
    iput-object p10, p0, Lh40/k;->o:Lbq0/b;

    .line 32
    .line 33
    iput-object p11, p0, Lh40/k;->p:Lf40/z2;

    .line 34
    .line 35
    move-object/from16 p3, p12

    .line 36
    .line 37
    iput-object p3, p0, Lh40/k;->q:Lrq0/d;

    .line 38
    .line 39
    move-object/from16 p3, p13

    .line 40
    .line 41
    iput-object p3, p0, Lh40/k;->r:Lf40/b3;

    .line 42
    .line 43
    invoke-virtual {p1}, Lf40/j0;->invoke()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Lg40/p;

    .line 48
    .line 49
    if-eqz p1, :cond_2

    .line 50
    .line 51
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 52
    .line 53
    .line 54
    move-result-object p2

    .line 55
    move-object p3, p2

    .line 56
    check-cast p3, Lh40/f;

    .line 57
    .line 58
    invoke-static {p1}, Lkp/na;->a(Lg40/p;)Lh40/m;

    .line 59
    .line 60
    .line 61
    move-result-object p4

    .line 62
    invoke-virtual {p7}, Lf40/b0;->invoke()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    check-cast p1, Lg40/p;

    .line 67
    .line 68
    if-eqz p1, :cond_1

    .line 69
    .line 70
    iget-object p1, p1, Lg40/p;->e:Ljava/lang/String;

    .line 71
    .line 72
    if-nez p1, :cond_0

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_0
    :goto_0
    move-object p6, p1

    .line 76
    goto :goto_2

    .line 77
    :cond_1
    :goto_1
    const-string p1, ""

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :goto_2
    const/4 p7, 0x0

    .line 81
    const/16 p8, 0xa

    .line 82
    .line 83
    const/4 p5, 0x0

    .line 84
    invoke-static/range {p3 .. p8}, Lh40/f;->a(Lh40/f;Lh40/m;ZLjava/lang/String;ZI)Lh40/f;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 89
    .line 90
    .line 91
    return-void

    .line 92
    :cond_2
    invoke-virtual {p2}, Ltr0/b;->invoke()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    return-void
.end method


# virtual methods
.method public final h()V
    .locals 7

    .line 1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    move-object v1, v0

    .line 6
    check-cast v1, Lh40/f;

    .line 7
    .line 8
    const/4 v5, 0x0

    .line 9
    const/4 v6, 0x7

    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x0

    .line 12
    const/4 v4, 0x0

    .line 13
    invoke-static/range {v1 .. v6}, Lh40/f;->a(Lh40/f;Lh40/m;ZLjava/lang/String;ZI)Lh40/f;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    check-cast v0, Lh40/f;

    .line 25
    .line 26
    iget-object v0, v0, Lh40/f;->a:Lh40/m;

    .line 27
    .line 28
    if-eqz v0, :cond_0

    .line 29
    .line 30
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    new-instance v2, Lg60/w;

    .line 35
    .line 36
    const/16 v3, 0xa

    .line 37
    .line 38
    const/4 v4, 0x0

    .line 39
    invoke-direct {v2, v3, p0, v0, v4}, Lg60/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 40
    .line 41
    .line 42
    const/4 p0, 0x3

    .line 43
    invoke-static {v1, v4, v4, v2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 44
    .line 45
    .line 46
    :cond_0
    return-void
.end method
