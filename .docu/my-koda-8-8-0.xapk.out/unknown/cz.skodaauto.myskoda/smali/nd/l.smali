.class public final Lnd/l;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljd/b;

.field public final e:Lxh/e;

.field public final f:Llx0/q;

.field public final g:Ljava/util/ArrayList;

.field public final h:Lu/x0;

.field public final i:Lyy0/l1;


# direct methods
.method public constructor <init>(Ljd/b;Lxh/e;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lnd/l;->d:Ljd/b;

    .line 5
    .line 6
    iput-object p2, p0, Lnd/l;->e:Lxh/e;

    .line 7
    .line 8
    invoke-static {p0}, Lzb/b;->F(Landroidx/lifecycle/b1;)Llx0/q;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Lnd/l;->f:Llx0/q;

    .line 13
    .line 14
    new-instance p1, Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lnd/l;->g:Ljava/util/ArrayList;

    .line 20
    .line 21
    new-instance p1, Lna/e;

    .line 22
    .line 23
    const/4 p2, 0x0

    .line 24
    const/4 v0, 0x3

    .line 25
    invoke-direct {p1, p0, p2, v0}, Lna/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 26
    .line 27
    .line 28
    new-instance p2, Lu/x0;

    .line 29
    .line 30
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-direct {p2, v0, p1}, Lu/x0;-><init>(Lr7/a;Lay0/n;)V

    .line 35
    .line 36
    .line 37
    iput-object p2, p0, Lnd/l;->h:Lu/x0;

    .line 38
    .line 39
    iget-object p1, p2, Lu/x0;->e:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p1, Lyy0/l1;

    .line 42
    .line 43
    new-instance p2, Llb0/y;

    .line 44
    .line 45
    const/4 v0, 0x2

    .line 46
    invoke-direct {p2, v0, p1, p0}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    const-wide/16 v0, 0x0

    .line 54
    .line 55
    const/4 v2, 0x2

    .line 56
    invoke-static {v2, v0, v1}, Lyy0/u1;->a(IJ)Lyy0/z1;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    new-instance v1, Llc/q;

    .line 61
    .line 62
    sget-object v2, Llc/a;->c:Llc/c;

    .line 63
    .line 64
    invoke-direct {v1, v2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    invoke-static {p2, p1, v0, v1}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    iput-object p1, p0, Lnd/l;->i:Lyy0/l1;

    .line 72
    .line 73
    return-void
.end method
