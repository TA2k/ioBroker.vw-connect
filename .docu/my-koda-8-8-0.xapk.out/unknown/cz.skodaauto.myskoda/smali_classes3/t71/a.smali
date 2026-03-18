.class public final Lt71/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ln71/c;

.field public b:Ls71/q;

.field public c:Ls71/m;

.field public d:Lu71/b;

.field public e:Ls71/l;

.field public f:Lt71/e;

.field public g:Lt71/b;


# direct methods
.method public constructor <init>(Ln71/c;Ls71/q;Ls71/m;Lu71/b;Ls71/l;Lt71/e;)V
    .locals 1

    .line 1
    const-string v0, "touchCell"

    .line 2
    .line 3
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lt71/a;->a:Ln71/c;

    .line 10
    .line 11
    iput-object p2, p0, Lt71/a;->b:Ls71/q;

    .line 12
    .line 13
    iput-object p3, p0, Lt71/a;->c:Ls71/m;

    .line 14
    .line 15
    iput-object p4, p0, Lt71/a;->d:Lu71/b;

    .line 16
    .line 17
    iput-object p5, p0, Lt71/a;->e:Ls71/l;

    .line 18
    .line 19
    iput-object p6, p0, Lt71/a;->f:Lt71/e;

    .line 20
    .line 21
    return-void
.end method

.method public static a(Lt71/a;Ls71/p;)Lt71/a;
    .locals 7

    .line 1
    iget-object v1, p0, Lt71/a;->a:Ln71/c;

    .line 2
    .line 3
    iget-object v3, p0, Lt71/a;->c:Ls71/m;

    .line 4
    .line 5
    iget-object v4, p0, Lt71/a;->d:Lu71/b;

    .line 6
    .line 7
    iget-object v5, p0, Lt71/a;->e:Ls71/l;

    .line 8
    .line 9
    iget-object v6, p0, Lt71/a;->f:Lt71/e;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const-string p0, "lifecycle"

    .line 15
    .line 16
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const-string p0, "sideEffect"

    .line 20
    .line 21
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    const-string p0, "touchCell"

    .line 25
    .line 26
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    new-instance v0, Lt71/a;

    .line 30
    .line 31
    move-object v2, p1

    .line 32
    invoke-direct/range {v0 .. v6}, Lt71/a;-><init>(Ln71/c;Ls71/q;Ls71/m;Lu71/b;Ls71/l;Lt71/e;)V

    .line 33
    .line 34
    .line 35
    return-object v0
.end method


# virtual methods
.method public final b(Lt71/b;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lt71/a;->g:Lt71/b;

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    invoke-interface {p1, p0}, Lt71/b;->lifecycleDidChange(Lt71/a;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-object p1, p0, Lt71/a;->g:Lt71/b;

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    invoke-interface {p1, p0}, Lt71/b;->userActionDidChange(Lt71/a;)V

    .line 13
    .line 14
    .line 15
    :cond_1
    iget-object p1, p0, Lt71/a;->g:Lt71/b;

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    invoke-interface {p1, p0}, Lt71/b;->sideEffectTriggered(Lt71/a;)V

    .line 20
    .line 21
    .line 22
    :cond_2
    iget-object p1, p0, Lt71/a;->g:Lt71/b;

    .line 23
    .line 24
    if-eqz p1, :cond_3

    .line 25
    .line 26
    invoke-interface {p1, p0}, Lt71/b;->touchPositionDidChange(Lt71/a;)V

    .line 27
    .line 28
    .line 29
    :cond_3
    iget-object p1, p0, Lt71/a;->g:Lt71/b;

    .line 30
    .line 31
    if-eqz p1, :cond_4

    .line 32
    .line 33
    invoke-interface {p1, p0}, Lt71/b;->screenDidChange(Lt71/a;)V

    .line 34
    .line 35
    .line 36
    :cond_4
    iget-object p1, p0, Lt71/a;->g:Lt71/b;

    .line 37
    .line 38
    if-eqz p1, :cond_5

    .line 39
    .line 40
    invoke-interface {p1, p0}, Lt71/b;->safetyInstructionDidChange(Lt71/a;)V

    .line 41
    .line 42
    .line 43
    :cond_5
    return-void
.end method
