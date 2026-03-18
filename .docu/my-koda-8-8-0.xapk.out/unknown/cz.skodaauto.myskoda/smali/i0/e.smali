.class public final Li0/e;
.super Landroidx/lifecycle/i0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public l:Lo/f;

.field public final m:Lb0/d;

.field public final n:Lf3/d;

.field public o:Landroidx/lifecycle/g0;


# direct methods
.method public constructor <init>(Lb0/d;)V
    .locals 2

    .line 1
    new-instance v0, Lf3/d;

    .line 2
    .line 3
    const/16 v1, 0x17

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lf3/d;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0}, Landroidx/lifecycle/g0;-><init>()V

    .line 9
    .line 10
    .line 11
    new-instance v1, Lo/f;

    .line 12
    .line 13
    invoke-direct {v1}, Lo/f;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v1, p0, Li0/e;->l:Lo/f;

    .line 17
    .line 18
    iput-object p1, p0, Li0/e;->m:Lb0/d;

    .line 19
    .line 20
    iput-object v0, p0, Li0/e;->n:Lf3/d;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final d()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Li0/e;->o:Landroidx/lifecycle/g0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Li0/e;->m:Lb0/d;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    invoke-virtual {v0}, Landroidx/lifecycle/g0;->d()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iget-object p0, p0, Li0/e;->n:Lf3/d;

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    return-object v0
.end method

.method public final g()V
    .locals 2

    .line 1
    iget-object p0, p0, Li0/e;->l:Lo/f;

    .line 2
    .line 3
    invoke-virtual {p0}, Lo/f;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    :goto_0
    move-object v0, p0

    .line 8
    check-cast v0, Lo/b;

    .line 9
    .line 10
    invoke-virtual {v0}, Lo/b;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    invoke-virtual {v0}, Lo/b;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, Ljava/util/Map$Entry;

    .line 21
    .line 22
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    check-cast v0, Landroidx/lifecycle/h0;

    .line 27
    .line 28
    iget-object v1, v0, Landroidx/lifecycle/h0;->a:Landroidx/lifecycle/g0;

    .line 29
    .line 30
    invoke-virtual {v1, v0}, Landroidx/lifecycle/g0;->f(Landroidx/lifecycle/j0;)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    return-void
.end method

.method public final h()V
    .locals 2

    .line 1
    iget-object p0, p0, Li0/e;->l:Lo/f;

    .line 2
    .line 3
    invoke-virtual {p0}, Lo/f;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    :goto_0
    move-object v0, p0

    .line 8
    check-cast v0, Lo/b;

    .line 9
    .line 10
    invoke-virtual {v0}, Lo/b;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    invoke-virtual {v0}, Lo/b;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, Ljava/util/Map$Entry;

    .line 21
    .line 22
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    check-cast v0, Landroidx/lifecycle/h0;

    .line 27
    .line 28
    invoke-virtual {v0}, Landroidx/lifecycle/h0;->b()V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    return-void
.end method
