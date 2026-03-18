.class public final Lwe/f;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lje/r;

.field public final e:Lne/b;

.field public final f:Ljava/lang/String;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/c2;

.field public final i:Lyy0/c2;

.field public final j:Lyy0/c2;

.field public final k:Lyy0/l1;


# direct methods
.method public constructor <init>(Lje/r;Lne/b;Ljava/lang/String;)V
    .locals 7

    .line 1
    const-string v0, "profileUuid"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lwe/f;->d:Lje/r;

    .line 10
    .line 11
    iput-object p2, p0, Lwe/f;->e:Lne/b;

    .line 12
    .line 13
    iput-object p3, p0, Lwe/f;->f:Ljava/lang/String;

    .line 14
    .line 15
    const-string p1, ""

    .line 16
    .line 17
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    iput-object p1, p0, Lwe/f;->g:Lyy0/c2;

    .line 22
    .line 23
    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 24
    .line 25
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 26
    .line 27
    .line 28
    move-result-object p3

    .line 29
    iput-object p3, p0, Lwe/f;->h:Lyy0/c2;

    .line 30
    .line 31
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 32
    .line 33
    .line 34
    move-result-object p2

    .line 35
    iput-object p2, p0, Lwe/f;->i:Lyy0/c2;

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    iput-object v1, p0, Lwe/f;->j:Lyy0/c2;

    .line 43
    .line 44
    new-instance v2, Lwe/e;

    .line 45
    .line 46
    invoke-direct {v2, p0, v0}, Lwe/e;-><init>(Lwe/f;Lkotlin/coroutines/Continuation;)V

    .line 47
    .line 48
    .line 49
    invoke-static {p1, p3, p2, v1, v2}, Lyy0/u;->l(Lyy0/i;Lyy0/i;Lyy0/i;Lyy0/i;Lay0/q;)Llb0/y;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    new-instance v0, Lwe/d;

    .line 58
    .line 59
    const/4 v5, 0x0

    .line 60
    const/4 v6, 0x0

    .line 61
    const-string v1, ""

    .line 62
    .line 63
    const-string v2, ""

    .line 64
    .line 65
    const/4 v3, 0x0

    .line 66
    const/4 v4, 0x0

    .line 67
    invoke-direct/range {v0 .. v6}, Lwe/d;-><init>(Ljava/lang/String;Ljava/lang/String;ZLlc/l;ZZ)V

    .line 68
    .line 69
    .line 70
    sget-object p3, Lyy0/u1;->a:Lyy0/w1;

    .line 71
    .line 72
    invoke-static {p1, p2, p3, v0}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    iput-object p1, p0, Lwe/f;->k:Lyy0/l1;

    .line 77
    .line 78
    return-void
.end method
