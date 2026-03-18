.class public final Lg11/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Z

.field public b:Z

.field public c:Z

.field public final d:Ljava/lang/Object;

.field public final e:Ljava/lang/Object;

.field public final f:Ljava/lang/Object;

.field public final g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lj11/y;Lb8/i;Lb8/i;Lg11/c;Lg11/d;Z)V
    .locals 1

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x1

    .line 10
    iput-boolean v0, p0, Lg11/c;->b:Z

    const/4 v0, 0x0

    .line 11
    iput-boolean v0, p0, Lg11/c;->c:Z

    .line 12
    iput-object p1, p0, Lg11/c;->d:Ljava/lang/Object;

    .line 13
    iput-object p2, p0, Lg11/c;->e:Ljava/lang/Object;

    .line 14
    iput-object p3, p0, Lg11/c;->f:Ljava/lang/Object;

    .line 15
    iput-boolean p6, p0, Lg11/c;->a:Z

    .line 16
    iput-object p4, p0, Lg11/c;->g:Ljava/lang/Object;

    .line 17
    iput-object p5, p0, Lg11/c;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lra/f;Lr1/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lg11/c;->d:Ljava/lang/Object;

    .line 3
    iput-object p2, p0, Lg11/c;->e:Ljava/lang/Object;

    .line 4
    new-instance p1, Lfv/b;

    const/16 p2, 0xe

    .line 5
    invoke-direct {p1, p2}, Lfv/b;-><init>(I)V

    .line 6
    iput-object p1, p0, Lg11/c;->f:Ljava/lang/Object;

    .line 7
    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object p1, p0, Lg11/c;->g:Ljava/lang/Object;

    const/4 p1, 0x1

    .line 8
    iput-boolean p1, p0, Lg11/c;->c:Z

    return-void
.end method


# virtual methods
.method public a()V
    .locals 3

    .line 1
    iget-object v0, p0, Lg11/c;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lra/f;

    .line 4
    .line 5
    invoke-interface {v0}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {v1}, Landroidx/lifecycle/r;->b()Landroidx/lifecycle/q;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    sget-object v2, Landroidx/lifecycle/q;->e:Landroidx/lifecycle/q;

    .line 14
    .line 15
    if-ne v1, v2, :cond_1

    .line 16
    .line 17
    iget-boolean v1, p0, Lg11/c;->a:Z

    .line 18
    .line 19
    if-nez v1, :cond_0

    .line 20
    .line 21
    iget-object v1, p0, Lg11/c;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v1, Lr1/b;

    .line 24
    .line 25
    invoke-virtual {v1}, Lr1/b;->invoke()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    invoke-interface {v0}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    new-instance v1, Landroidx/lifecycle/m;

    .line 33
    .line 34
    const/4 v2, 0x3

    .line 35
    invoke-direct {v1, p0, v2}, Landroidx/lifecycle/m;-><init>(Ljava/lang/Object;I)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0, v1}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 39
    .line 40
    .line 41
    const/4 v0, 0x1

    .line 42
    iput-boolean v0, p0, Lg11/c;->a:Z

    .line 43
    .line 44
    return-void

    .line 45
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string v0, "SavedStateRegistry was already attached."

    .line 48
    .line 49
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string v0, "Restarter must be created only during owner\'s initialization stage"

    .line 56
    .line 57
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0
.end method
