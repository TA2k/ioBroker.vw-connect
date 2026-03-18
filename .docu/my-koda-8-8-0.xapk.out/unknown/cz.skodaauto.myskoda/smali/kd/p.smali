.class public final Lkd/p;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lxh/e;

.field public final e:Lay0/k;

.field public final f:Ljd/b;

.field public final g:Llx0/q;

.field public final h:Lyy0/c2;

.field public i:Lcd/n;

.field public final j:Lu/x0;

.field public final k:Lyy0/l1;

.field public l:Z


# direct methods
.method public constructor <init>(Lxh/e;Lay0/k;Ljd/b;)V
    .locals 7

    .line 1
    const-string v0, "exportFilters"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lkd/p;->d:Lxh/e;

    .line 10
    .line 11
    iput-object p2, p0, Lkd/p;->e:Lay0/k;

    .line 12
    .line 13
    iput-object p3, p0, Lkd/p;->f:Ljd/b;

    .line 14
    .line 15
    invoke-static {p0}, Lzb/b;->F(Landroidx/lifecycle/b1;)Llx0/q;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    iput-object p1, p0, Lkd/p;->g:Llx0/q;

    .line 20
    .line 21
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 22
    .line 23
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    iput-object p1, p0, Lkd/p;->h:Lyy0/c2;

    .line 28
    .line 29
    new-instance p2, Lcd/n;

    .line 30
    .line 31
    invoke-direct {p2}, Lcd/n;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object p2, p0, Lkd/p;->i:Lcd/n;

    .line 35
    .line 36
    new-instance p2, Lk31/t;

    .line 37
    .line 38
    const/4 p3, 0x0

    .line 39
    const/16 v0, 0x8

    .line 40
    .line 41
    invoke-direct {p2, p0, p3, v0}, Lk31/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 42
    .line 43
    .line 44
    new-instance p3, Lu/x0;

    .line 45
    .line 46
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-direct {p3, v0, p2}, Lu/x0;-><init>(Lr7/a;Lay0/n;)V

    .line 51
    .line 52
    .line 53
    iput-object p3, p0, Lkd/p;->j:Lu/x0;

    .line 54
    .line 55
    iget-object p2, p3, Lu/x0;->e:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p2, Lyy0/l1;

    .line 58
    .line 59
    new-instance v0, Lkd/o;

    .line 60
    .line 61
    const-string v6, "onStateUpdate(Lcariad/charging/multicharge/common/presentation/LoadState;Ljava/util/List;)Lcariad/charging/multicharge/common/presentation/loadingcontenterror/UiState;"

    .line 62
    .line 63
    const/4 v2, 0x4

    .line 64
    const/4 v1, 0x3

    .line 65
    const-class v3, Lkd/p;

    .line 66
    .line 67
    const-string v5, "onStateUpdate"

    .line 68
    .line 69
    move-object v4, p0

    .line 70
    invoke-direct/range {v0 .. v6}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    new-instance p0, Lbn0/f;

    .line 74
    .line 75
    const/4 p3, 0x5

    .line 76
    invoke-direct {p0, p2, p1, v0, p3}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 77
    .line 78
    .line 79
    invoke-static {v4}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    const-wide/16 p2, 0x0

    .line 84
    .line 85
    const/4 v0, 0x2

    .line 86
    invoke-static {v0, p2, p3}, Lyy0/u1;->a(IJ)Lyy0/z1;

    .line 87
    .line 88
    .line 89
    move-result-object p2

    .line 90
    new-instance p3, Llc/q;

    .line 91
    .line 92
    sget-object v0, Llc/a;->c:Llc/c;

    .line 93
    .line 94
    invoke-direct {p3, v0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    invoke-static {p0, p1, p2, p3}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    iput-object p0, v4, Lkd/p;->k:Lyy0/l1;

    .line 102
    .line 103
    return-void
.end method


# virtual methods
.method public final a(Lkd/a;)Lkd/a;
    .locals 9

    .line 1
    iget-object v0, p1, Lkd/a;->a:Lkd/q;

    .line 2
    .line 3
    sget-object v1, Lkd/q;->g:Lkd/q;

    .line 4
    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    iget-object v2, p0, Lkd/p;->i:Lcd/n;

    .line 8
    .line 9
    const/4 v7, 0x0

    .line 10
    const/16 v8, 0x13

    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    const/4 v4, 0x0

    .line 14
    const/4 v5, 0x0

    .line 15
    const/4 v6, 0x0

    .line 16
    invoke-static/range {v2 .. v8}, Lcd/n;->a(Lcd/n;Ljava/util/ArrayList;Ljava/util/ArrayList;Lgz0/p;Lgz0/p;ZI)Lcd/n;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    iput-object v0, p0, Lkd/p;->i:Lcd/n;

    .line 21
    .line 22
    :cond_0
    iget-object p0, p1, Lkd/a;->e:Ljava/lang/String;

    .line 23
    .line 24
    const/4 v0, 0x0

    .line 25
    const/16 v1, 0x13

    .line 26
    .line 27
    invoke-static {p1, p0, v0, v1}, Lkd/a;->a(Lkd/a;Ljava/lang/String;ZI)Lkd/a;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method

.method public final b()V
    .locals 4

    .line 1
    new-instance v0, Ljd/a;

    .line 2
    .line 3
    iget-object v1, p0, Lkd/p;->h:Lyy0/c2;

    .line 4
    .line 5
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    check-cast v1, Ljava/util/List;

    .line 10
    .line 11
    iget-object v2, p0, Lkd/p;->i:Lcd/n;

    .line 12
    .line 13
    iget-object v3, v2, Lcd/n;->c:Lgz0/p;

    .line 14
    .line 15
    iget-object v2, v2, Lcd/n;->d:Lgz0/p;

    .line 16
    .line 17
    invoke-direct {v0, v1, v3, v2}, Ljd/a;-><init>(Ljava/util/List;Lgz0/p;Lgz0/p;)V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lkd/p;->e:Lay0/k;

    .line 21
    .line 22
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    return-void
.end method
