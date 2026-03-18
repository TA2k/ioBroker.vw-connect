.class public final Ldi/o;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Lxh/e;

.field public final f:Lxh/e;

.field public final g:Lyj/b;

.field public final h:Lyj/b;

.field public final i:Lai/e;

.field public final j:Lag/c;

.field public final k:Lag/c;

.field public final l:Lai/e;

.field public final m:Lxh/e;

.field public final n:Lzb/s0;

.field public final o:Lyy0/c2;

.field public final p:Lyy0/c2;

.field public final q:Lyy0/c2;

.field public final r:Lyy0/c2;

.field public final s:Lyy0/l1;

.field public t:Lzg/h;

.field public final u:Llx0/q;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lxh/e;Lxh/e;Lyj/b;Lyj/b;Lai/e;Lag/c;Lag/c;Lai/e;Lxh/e;Lzb/s0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ldi/o;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Ldi/o;->e:Lxh/e;

    .line 7
    .line 8
    iput-object p3, p0, Ldi/o;->f:Lxh/e;

    .line 9
    .line 10
    iput-object p4, p0, Ldi/o;->g:Lyj/b;

    .line 11
    .line 12
    iput-object p5, p0, Ldi/o;->h:Lyj/b;

    .line 13
    .line 14
    iput-object p6, p0, Ldi/o;->i:Lai/e;

    .line 15
    .line 16
    iput-object p7, p0, Ldi/o;->j:Lag/c;

    .line 17
    .line 18
    iput-object p8, p0, Ldi/o;->k:Lag/c;

    .line 19
    .line 20
    iput-object p9, p0, Ldi/o;->l:Lai/e;

    .line 21
    .line 22
    iput-object p10, p0, Ldi/o;->m:Lxh/e;

    .line 23
    .line 24
    iput-object p11, p0, Ldi/o;->n:Lzb/s0;

    .line 25
    .line 26
    const/4 p1, 0x0

    .line 27
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    iput-object p2, p0, Ldi/o;->o:Lyy0/c2;

    .line 32
    .line 33
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 34
    .line 35
    .line 36
    move-result-object p3

    .line 37
    iput-object p3, p0, Ldi/o;->p:Lyy0/c2;

    .line 38
    .line 39
    sget-object p4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 40
    .line 41
    invoke-static {p4}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 42
    .line 43
    .line 44
    move-result-object p4

    .line 45
    iput-object p4, p0, Ldi/o;->q:Lyy0/c2;

    .line 46
    .line 47
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 48
    .line 49
    .line 50
    move-result-object p5

    .line 51
    iput-object p5, p0, Ldi/o;->r:Lyy0/c2;

    .line 52
    .line 53
    new-instance p6, Ldi/n;

    .line 54
    .line 55
    const/4 p7, 0x5

    .line 56
    const/4 p8, 0x0

    .line 57
    invoke-direct {p6, p7, p1, p8}, Ldi/n;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 58
    .line 59
    .line 60
    invoke-static {p2, p3, p4, p5, p6}, Lyy0/u;->l(Lyy0/i;Lyy0/i;Lyy0/i;Lyy0/i;Lay0/q;)Llb0/y;

    .line 61
    .line 62
    .line 63
    move-result-object p2

    .line 64
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 65
    .line 66
    .line 67
    move-result-object p3

    .line 68
    const/4 p4, 0x3

    .line 69
    const-wide/16 p5, 0x0

    .line 70
    .line 71
    invoke-static {p4, p5, p6}, Lyy0/u1;->a(IJ)Lyy0/z1;

    .line 72
    .line 73
    .line 74
    move-result-object p5

    .line 75
    new-instance p6, Llc/q;

    .line 76
    .line 77
    sget-object p7, Llc/a;->c:Llc/c;

    .line 78
    .line 79
    invoke-direct {p6, p7}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    invoke-static {p2, p3, p5, p6}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 83
    .line 84
    .line 85
    move-result-object p2

    .line 86
    iput-object p2, p0, Ldi/o;->s:Lyy0/l1;

    .line 87
    .line 88
    invoke-static {p0}, Lzb/b;->F(Landroidx/lifecycle/b1;)Llx0/q;

    .line 89
    .line 90
    .line 91
    move-result-object p2

    .line 92
    iput-object p2, p0, Ldi/o;->u:Llx0/q;

    .line 93
    .line 94
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 95
    .line 96
    .line 97
    move-result-object p2

    .line 98
    new-instance p3, Ldi/m;

    .line 99
    .line 100
    const/4 p5, 0x0

    .line 101
    invoke-direct {p3, p0, p1, p5}, Ldi/m;-><init>(Ldi/o;Lkotlin/coroutines/Continuation;I)V

    .line 102
    .line 103
    .line 104
    invoke-static {p2, p1, p1, p3, p4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 105
    .line 106
    .line 107
    return-void
.end method

.method public static final a(Ldi/o;)V
    .locals 5

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, v0}, Ldi/o;->b(Z)V

    .line 3
    .line 4
    .line 5
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    new-instance v1, Laa/i0;

    .line 10
    .line 11
    const/4 v2, 0x5

    .line 12
    const/4 v3, 0x0

    .line 13
    invoke-direct {v1, p0, v3, v2}, Laa/i0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    const/4 v2, 0x3

    .line 17
    invoke-static {v0, v3, v3, v1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 18
    .line 19
    .line 20
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    new-instance v1, Lc80/l;

    .line 25
    .line 26
    const/16 v4, 0x14

    .line 27
    .line 28
    invoke-direct {v1, p0, v3, v4}, Lc80/l;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v0, v3, v3, v1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 32
    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public final b(Z)V
    .locals 1

    .line 1
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iget-object p0, p0, Ldi/o;->q:Lyy0/c2;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    return-void
.end method
