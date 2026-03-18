.class public final Lno0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Llo0/c;

.field public final b:Lno0/d;

.field public final c:Ljr0/f;

.field public final d:Ljr0/c;


# direct methods
.method public constructor <init>(Llo0/c;Lno0/d;Ljr0/f;Ljr0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lno0/c;->a:Llo0/c;

    .line 5
    .line 6
    iput-object p2, p0, Lno0/c;->b:Lno0/d;

    .line 7
    .line 8
    iput-object p3, p0, Lno0/c;->c:Ljr0/f;

    .line 9
    .line 10
    iput-object p4, p0, Lno0/c;->d:Ljr0/c;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lno0/a;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    const-string v0, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lno0/c;->a:Llo0/c;

    .line 15
    .line 16
    iget-object v2, v0, Llo0/c;->a:Lxl0/f;

    .line 17
    .line 18
    new-instance v3, Llo0/b;

    .line 19
    .line 20
    const/4 v4, 0x0

    .line 21
    const/4 v5, 0x0

    .line 22
    invoke-direct {v3, v4, v0, v1, v5}, Llo0/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    new-instance v0, Lkq0/a;

    .line 26
    .line 27
    const/16 v1, 0x17

    .line 28
    .line 29
    invoke-direct {v0, v1}, Lkq0/a;-><init>(I)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v2, v3, v0, v5}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    new-instance v1, Llb0/q0;

    .line 37
    .line 38
    const/16 v2, 0x1d

    .line 39
    .line 40
    invoke-direct {v1, p0, v5, v2}, Llb0/q0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 41
    .line 42
    .line 43
    new-instance v2, Lne0/n;

    .line 44
    .line 45
    const/4 v3, 0x5

    .line 46
    invoke-direct {v2, v0, v1, v3}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 47
    .line 48
    .line 49
    new-instance v0, Lno0/b;

    .line 50
    .line 51
    const/4 v1, 0x0

    .line 52
    sget-object v3, Loo0/a;->b:Loo0/a;

    .line 53
    .line 54
    invoke-direct {v0, p0, v3, v5, v1}, Lno0/b;-><init>(Lno0/c;Lkr0/c;Lkotlin/coroutines/Continuation;I)V

    .line 55
    .line 56
    .line 57
    new-instance v1, Lne0/n;

    .line 58
    .line 59
    invoke-direct {v1, v0, v2}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 60
    .line 61
    .line 62
    new-instance v0, Lno0/b;

    .line 63
    .line 64
    const/4 v2, 0x1

    .line 65
    invoke-direct {v0, p0, v3, v5, v2}, Lno0/b;-><init>(Lno0/c;Lkr0/c;Lkotlin/coroutines/Continuation;I)V

    .line 66
    .line 67
    .line 68
    invoke-static {v0, v1}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    new-instance v1, Laa/s;

    .line 73
    .line 74
    const/16 v2, 0x19

    .line 75
    .line 76
    invoke-direct {v1, v2, p0, v3, v5}, Laa/s;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 77
    .line 78
    .line 79
    invoke-static {v1, v0}, Lbb/j0;->e(Lay0/n;Lyy0/i;)Lne0/n;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0
.end method
