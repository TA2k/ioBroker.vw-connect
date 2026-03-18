.class public final Lne/k;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lay0/a;

.field public final e:La30/b;

.field public final f:La90/s;

.field public final g:Lne/b;

.field public final h:Lyy0/c2;

.field public final i:Lyy0/l1;


# direct methods
.method public constructor <init>(Lay0/a;La30/b;La90/s;Lne/b;)V
    .locals 1

    .line 1
    const-string v0, "goToWizard"

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
    iput-object p1, p0, Lne/k;->d:Lay0/a;

    .line 10
    .line 11
    iput-object p2, p0, Lne/k;->e:La30/b;

    .line 12
    .line 13
    iput-object p3, p0, Lne/k;->f:La90/s;

    .line 14
    .line 15
    iput-object p4, p0, Lne/k;->g:Lne/b;

    .line 16
    .line 17
    sget-object p1, Lne/i;->e:Lne/i;

    .line 18
    .line 19
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    iput-object p1, p0, Lne/k;->h:Lyy0/c2;

    .line 24
    .line 25
    new-instance p2, Lyy0/l1;

    .line 26
    .line 27
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 28
    .line 29
    .line 30
    iput-object p2, p0, Lne/k;->i:Lyy0/l1;

    .line 31
    .line 32
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    new-instance p2, Lne/j;

    .line 37
    .line 38
    const/4 p3, 0x1

    .line 39
    const/4 p4, 0x0

    .line 40
    invoke-direct {p2, p0, p4, p3}, Lne/j;-><init>(Lne/k;Lkotlin/coroutines/Continuation;I)V

    .line 41
    .line 42
    .line 43
    const/4 p0, 0x3

    .line 44
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 45
    .line 46
    .line 47
    return-void
.end method

.method public static final a(Lne/k;Ljava/lang/Throwable;)V
    .locals 7

    .line 1
    iget-object p0, p0, Lne/k;->h:Lyy0/c2;

    .line 2
    .line 3
    :cond_0
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Lne/i;

    .line 9
    .line 10
    invoke-static {p1}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 11
    .line 12
    .line 13
    move-result-object v5

    .line 14
    const/4 v6, 0x1

    .line 15
    const/4 v2, 0x0

    .line 16
    const/4 v3, 0x0

    .line 17
    const/4 v4, 0x0

    .line 18
    invoke-static/range {v1 .. v6}, Lne/i;->a(Lne/i;Ljp/na;ZZLlc/l;I)Lne/i;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-virtual {p0, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    return-void
.end method
