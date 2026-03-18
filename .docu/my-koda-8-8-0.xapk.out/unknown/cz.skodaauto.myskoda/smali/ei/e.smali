.class public final Lei/e;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lyj/b;

.field public final e:Lai/e;

.field public final f:Lai/e;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/c2;

.field public final i:Lyy0/c2;

.field public final j:Lyy0/c2;

.field public final k:Lyy0/l1;

.field public final l:Llx0/q;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lxh/e;Lxh/e;Lyj/b;Lyj/b;Lai/e;Lag/c;Lag/c;Lai/e;Lxh/e;Lbi/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p5, p0, Lei/e;->d:Lyj/b;

    .line 5
    .line 6
    iput-object p6, p0, Lei/e;->e:Lai/e;

    .line 7
    .line 8
    iput-object p9, p0, Lei/e;->f:Lai/e;

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 12
    .line 13
    .line 14
    move-result-object p2

    .line 15
    iput-object p2, p0, Lei/e;->g:Lyy0/c2;

    .line 16
    .line 17
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 18
    .line 19
    .line 20
    move-result-object p3

    .line 21
    iput-object p3, p0, Lei/e;->h:Lyy0/c2;

    .line 22
    .line 23
    sget-object p4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 24
    .line 25
    invoke-static {p4}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 26
    .line 27
    .line 28
    move-result-object p4

    .line 29
    iput-object p4, p0, Lei/e;->i:Lyy0/c2;

    .line 30
    .line 31
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 32
    .line 33
    .line 34
    move-result-object p5

    .line 35
    iput-object p5, p0, Lei/e;->j:Lyy0/c2;

    .line 36
    .line 37
    new-instance p6, Ldi/n;

    .line 38
    .line 39
    const/4 p7, 0x5

    .line 40
    const/4 p8, 0x1

    .line 41
    invoke-direct {p6, p7, p1, p8}, Ldi/n;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 42
    .line 43
    .line 44
    invoke-static {p2, p3, p4, p5, p6}, Lyy0/u;->l(Lyy0/i;Lyy0/i;Lyy0/i;Lyy0/i;Lay0/q;)Llb0/y;

    .line 45
    .line 46
    .line 47
    move-result-object p2

    .line 48
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 49
    .line 50
    .line 51
    move-result-object p3

    .line 52
    const/4 p4, 0x3

    .line 53
    const-wide/16 p5, 0x0

    .line 54
    .line 55
    invoke-static {p4, p5, p6}, Lyy0/u1;->a(IJ)Lyy0/z1;

    .line 56
    .line 57
    .line 58
    move-result-object p5

    .line 59
    new-instance p6, Llc/q;

    .line 60
    .line 61
    sget-object p7, Llc/a;->c:Llc/c;

    .line 62
    .line 63
    invoke-direct {p6, p7}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    invoke-static {p2, p3, p5, p6}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    iput-object p2, p0, Lei/e;->k:Lyy0/l1;

    .line 71
    .line 72
    invoke-static {p0}, Lzb/b;->F(Landroidx/lifecycle/b1;)Llx0/q;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    iput-object p2, p0, Lei/e;->l:Llx0/q;

    .line 77
    .line 78
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    new-instance p3, Ldm0/h;

    .line 83
    .line 84
    const/16 p5, 0x9

    .line 85
    .line 86
    invoke-direct {p3, p0, p1, p5}, Ldm0/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 87
    .line 88
    .line 89
    invoke-static {p2, p1, p1, p3, p4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 90
    .line 91
    .line 92
    return-void
.end method
