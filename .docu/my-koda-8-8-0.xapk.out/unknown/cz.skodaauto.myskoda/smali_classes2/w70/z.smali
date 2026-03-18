.class public final Lw70/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbq0/e;

.field public final b:Lbq0/h;

.field public final c:Lu70/c;


# direct methods
.method public constructor <init>(Lbq0/e;Lbq0/h;Lu70/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw70/z;->a:Lbq0/e;

    .line 5
    .line 6
    iput-object p2, p0, Lw70/z;->b:Lbq0/h;

    .line 7
    .line 8
    iput-object p3, p0, Lw70/z;->c:Lu70/c;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Lw70/z;->a:Lbq0/e;

    .line 2
    .line 3
    invoke-virtual {v0}, Lbq0/e;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lcq0/q;

    .line 8
    .line 9
    instance-of v1, v0, Lcq0/o;

    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    new-instance p0, Lne0/e;

    .line 14
    .line 15
    check-cast v0, Lcq0/o;

    .line 16
    .line 17
    iget-object v0, v0, Lcq0/o;->a:Lcq0/n;

    .line 18
    .line 19
    invoke-direct {p0, v0}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    new-instance v0, Lyy0/m;

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    invoke-direct {v0, p0, v1}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 26
    .line 27
    .line 28
    return-object v0

    .line 29
    :cond_0
    instance-of v1, v0, Lcq0/p;

    .line 30
    .line 31
    if-eqz v1, :cond_1

    .line 32
    .line 33
    check-cast v0, Lcq0/p;

    .line 34
    .line 35
    iget-object v0, v0, Lcq0/p;->a:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v1, p0, Lw70/z;->c:Lu70/c;

    .line 38
    .line 39
    const-string v2, "id"

    .line 40
    .line 41
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    iget-object v2, v1, Lu70/c;->a:Lxl0/f;

    .line 45
    .line 46
    new-instance v3, Llo0/b;

    .line 47
    .line 48
    const/16 v4, 0x1a

    .line 49
    .line 50
    const/4 v5, 0x0

    .line 51
    invoke-direct {v3, v4, v1, v0, v5}, Llo0/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 52
    .line 53
    .line 54
    new-instance v0, Lu2/d;

    .line 55
    .line 56
    const/4 v1, 0x5

    .line 57
    invoke-direct {v0, v1}, Lu2/d;-><init>(I)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v2, v3, v0, v5}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    new-instance v1, Ls10/a0;

    .line 65
    .line 66
    const/16 v2, 0x1d

    .line 67
    .line 68
    invoke-direct {v1, p0, v5, v2}, Ls10/a0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 69
    .line 70
    .line 71
    invoke-static {v1, v0}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    return-object p0

    .line 76
    :cond_1
    if-nez v0, :cond_2

    .line 77
    .line 78
    new-instance v0, Lne0/c;

    .line 79
    .line 80
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 81
    .line 82
    const-string p0, "Service detail is not available and service detail id is not set."

    .line 83
    .line 84
    invoke-direct {v1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    const/4 v4, 0x0

    .line 88
    const/16 v5, 0x1e

    .line 89
    .line 90
    const/4 v2, 0x0

    .line 91
    const/4 v3, 0x0

    .line 92
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 93
    .line 94
    .line 95
    new-instance p0, Lyy0/m;

    .line 96
    .line 97
    const/4 v1, 0x0

    .line 98
    invoke-direct {p0, v0, v1}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 99
    .line 100
    .line 101
    return-object p0

    .line 102
    :cond_2
    new-instance p0, La8/r0;

    .line 103
    .line 104
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 105
    .line 106
    .line 107
    throw p0
.end method
