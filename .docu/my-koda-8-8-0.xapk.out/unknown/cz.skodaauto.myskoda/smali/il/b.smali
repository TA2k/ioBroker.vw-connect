.class public final Lil/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/util/ArrayList;

.field public final b:Ljava/util/ArrayList;

.field public final c:Ljava/util/ArrayList;

.field public final d:Ljava/util/ArrayList;

.field public final e:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Lil/c;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iget-object v0, p1, Lil/c;->a:Ljava/util/List;

    .line 3
    check-cast v0, Ljava/util/Collection;

    invoke-static {v0}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v0

    iput-object v0, p0, Lil/b;->a:Ljava/util/ArrayList;

    .line 4
    iget-object v0, p1, Lil/c;->b:Ljava/util/List;

    .line 5
    check-cast v0, Ljava/util/Collection;

    invoke-static {v0}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v0

    iput-object v0, p0, Lil/b;->b:Ljava/util/ArrayList;

    .line 6
    iget-object v0, p1, Lil/c;->c:Ljava/util/List;

    .line 7
    check-cast v0, Ljava/util/Collection;

    invoke-static {v0}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v0

    iput-object v0, p0, Lil/b;->c:Ljava/util/ArrayList;

    .line 8
    iget-object v0, p1, Lil/c;->d:Ljava/util/List;

    .line 9
    check-cast v0, Ljava/util/Collection;

    invoke-static {v0}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v0

    iput-object v0, p0, Lil/b;->d:Ljava/util/ArrayList;

    .line 10
    iget-object p1, p1, Lil/c;->e:Ljava/util/List;

    .line 11
    check-cast p1, Ljava/util/Collection;

    invoke-static {p1}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object p1

    iput-object p1, p0, Lil/b;->e:Ljava/util/ArrayList;

    return-void
.end method

.method public constructor <init>(Lyl/d;)V
    .locals 5

    .line 12
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 13
    iget-object v0, p1, Lyl/d;->a:Ljava/util/List;

    .line 14
    check-cast v0, Ljava/util/Collection;

    invoke-static {v0}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v0

    iput-object v0, p0, Lil/b;->a:Ljava/util/ArrayList;

    .line 15
    iget-object v0, p1, Lyl/d;->b:Ljava/util/List;

    .line 16
    check-cast v0, Ljava/util/Collection;

    invoke-static {v0}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v0

    iput-object v0, p0, Lil/b;->b:Ljava/util/ArrayList;

    .line 17
    iget-object v0, p1, Lyl/d;->c:Ljava/util/List;

    .line 18
    check-cast v0, Ljava/util/Collection;

    invoke-static {v0}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v0

    iput-object v0, p0, Lil/b;->c:Ljava/util/ArrayList;

    .line 19
    iget-object v0, p1, Lyl/d;->f:Llx0/q;

    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/List;

    .line 20
    check-cast v0, Ljava/lang/Iterable;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 21
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    .line 22
    check-cast v2, Llx0/l;

    .line 23
    new-instance v3, Ly1/i;

    const/16 v4, 0x8

    invoke-direct {v3, v2, v4}, Ly1/i;-><init>(Ljava/lang/Object;I)V

    .line 24
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    .line 25
    :cond_0
    iput-object v1, p0, Lil/b;->d:Ljava/util/ArrayList;

    .line 26
    iget-object p1, p1, Lyl/d;->g:Llx0/q;

    invoke-virtual {p1}, Llx0/q;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/List;

    .line 27
    check-cast p1, Ljava/lang/Iterable;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 28
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    .line 29
    check-cast v1, Lbm/j;

    .line 30
    new-instance v2, Lyl/c;

    const/4 v3, 0x0

    invoke-direct {v2, v1, v3}, Lyl/c;-><init>(Lbm/j;I)V

    .line 31
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    .line 32
    :cond_1
    iput-object v0, p0, Lil/b;->e:Ljava/util/ArrayList;

    return-void
.end method


# virtual methods
.method public a(Ldm/f;Lhy0/d;)V
    .locals 2

    .line 1
    new-instance v0, Lyj/b;

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    invoke-direct {v0, v1, p1, p2}, Lyj/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lil/b;->d:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-interface {p0, v0}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public b(Lgm/a;Lhy0/d;)V
    .locals 1

    .line 1
    new-instance v0, Llx0/l;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lil/b;->b:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-interface {p0, v0}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public c(Lnl/f;Ljava/lang/Class;)V
    .locals 1

    .line 1
    new-instance v0, Llx0/l;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lil/b;->d:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public d(Lql/a;Ljava/lang/Class;)V
    .locals 1

    .line 1
    new-instance v0, Llx0/l;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lil/b;->b:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    return-void
.end method
