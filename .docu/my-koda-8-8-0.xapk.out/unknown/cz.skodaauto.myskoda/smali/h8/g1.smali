.class public abstract Lh8/g1;
.super Lh8/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final k:Lh8/a;


# direct methods
.method public constructor <init>(Lh8/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lh8/k;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh8/g1;->k:Lh8/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public A()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lh8/g1;->z()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final f()Lt7/p0;
    .locals 0

    .line 1
    iget-object p0, p0, Lh8/g1;->k:Lh8/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Lh8/a;->f()Lt7/p0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final g()Lt7/x;
    .locals 0

    .line 1
    iget-object p0, p0, Lh8/g1;->k:Lh8/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Lh8/a;->g()Lt7/x;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final h()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh8/g1;->k:Lh8/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Lh8/a;->h()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final k(Ly7/z;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lh8/k;->j:Ly7/z;

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    invoke-static {p1}, Lw7/w;->k(Lm8/k;)Landroid/os/Handler;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    iput-object p1, p0, Lh8/k;->i:Landroid/os/Handler;

    .line 9
    .line 10
    invoke-virtual {p0}, Lh8/g1;->A()V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public r(Lt7/x;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh8/g1;->k:Lh8/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lh8/a;->r(Lt7/x;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final s(Ljava/lang/Object;Lh8/b0;)Lh8/b0;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/Void;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lh8/g1;->x(Lh8/b0;)Lh8/b0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final t(JLjava/lang/Object;)J
    .locals 0

    .line 1
    check-cast p3, Ljava/lang/Void;

    .line 2
    .line 3
    return-wide p1
.end method

.method public final u(ILjava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p2, Ljava/lang/Void;

    .line 2
    .line 3
    return p1
.end method

.method public final v(Ljava/lang/Object;Lh8/a;Lt7/p0;)V
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/Void;

    .line 2
    .line 3
    invoke-virtual {p0, p3}, Lh8/g1;->y(Lt7/p0;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public x(Lh8/b0;)Lh8/b0;
    .locals 0

    .line 1
    return-object p1
.end method

.method public abstract y(Lt7/p0;)V
.end method

.method public final z()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lh8/g1;->k:Lh8/a;

    .line 3
    .line 4
    invoke-virtual {p0, v0, v1}, Lh8/k;->w(Ljava/lang/Object;Lh8/a;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method
