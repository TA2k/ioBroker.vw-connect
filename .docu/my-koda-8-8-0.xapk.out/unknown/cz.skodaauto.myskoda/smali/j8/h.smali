.class public final Lj8/h;
.super Lt7/t0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final A:Z

.field public final B:Landroid/util/SparseArray;

.field public final C:Landroid/util/SparseBooleanArray;

.field public final u:Z

.field public final v:Z

.field public final w:Z

.field public final x:Z

.field public final y:Z

.field public final z:Z


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 17
    invoke-direct {p0}, Lt7/t0;-><init>()V

    .line 18
    new-instance v0, Landroid/util/SparseArray;

    invoke-direct {v0}, Landroid/util/SparseArray;-><init>()V

    iput-object v0, p0, Lj8/h;->B:Landroid/util/SparseArray;

    .line 19
    new-instance v0, Landroid/util/SparseBooleanArray;

    invoke-direct {v0}, Landroid/util/SparseBooleanArray;-><init>()V

    iput-object v0, p0, Lj8/h;->C:Landroid/util/SparseBooleanArray;

    const/4 v0, 0x1

    .line 20
    iput-boolean v0, p0, Lj8/h;->u:Z

    .line 21
    iput-boolean v0, p0, Lj8/h;->v:Z

    .line 22
    iput-boolean v0, p0, Lj8/h;->w:Z

    .line 23
    iput-boolean v0, p0, Lj8/h;->x:Z

    .line 24
    iput-boolean v0, p0, Lj8/h;->y:Z

    .line 25
    iput-boolean v0, p0, Lj8/h;->z:Z

    .line 26
    iput-boolean v0, p0, Lj8/h;->A:Z

    return-void
.end method

.method public constructor <init>(Lj8/i;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    invoke-virtual {p0, p1}, Lt7/t0;->c(Lt7/u0;)V

    .line 3
    iget-boolean v0, p1, Lj8/i;->u:Z

    iput-boolean v0, p0, Lj8/h;->u:Z

    .line 4
    iget-boolean v0, p1, Lj8/i;->v:Z

    iput-boolean v0, p0, Lj8/h;->v:Z

    .line 5
    iget-boolean v0, p1, Lj8/i;->w:Z

    iput-boolean v0, p0, Lj8/h;->w:Z

    .line 6
    iget-boolean v0, p1, Lj8/i;->x:Z

    iput-boolean v0, p0, Lj8/h;->x:Z

    .line 7
    iget-boolean v0, p1, Lj8/i;->y:Z

    iput-boolean v0, p0, Lj8/h;->y:Z

    .line 8
    iget-boolean v0, p1, Lj8/i;->z:Z

    iput-boolean v0, p0, Lj8/h;->z:Z

    .line 9
    iget-boolean v0, p1, Lj8/i;->A:Z

    iput-boolean v0, p0, Lj8/h;->A:Z

    .line 10
    iget-object v0, p1, Lj8/i;->B:Landroid/util/SparseArray;

    .line 11
    new-instance v1, Landroid/util/SparseArray;

    invoke-direct {v1}, Landroid/util/SparseArray;-><init>()V

    const/4 v2, 0x0

    .line 12
    :goto_0
    invoke-virtual {v0}, Landroid/util/SparseArray;->size()I

    move-result v3

    if-ge v2, v3, :cond_0

    .line 13
    invoke-virtual {v0, v2}, Landroid/util/SparseArray;->keyAt(I)I

    move-result v3

    new-instance v4, Ljava/util/HashMap;

    invoke-virtual {v0, v2}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/util/Map;

    invoke-direct {v4, v5}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    invoke-virtual {v1, v3, v4}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 14
    :cond_0
    iput-object v1, p0, Lj8/h;->B:Landroid/util/SparseArray;

    .line 15
    iget-object p1, p1, Lj8/i;->C:Landroid/util/SparseBooleanArray;

    .line 16
    invoke-virtual {p1}, Landroid/util/SparseBooleanArray;->clone()Landroid/util/SparseBooleanArray;

    move-result-object p1

    iput-object p1, p0, Lj8/h;->C:Landroid/util/SparseBooleanArray;

    return-void
.end method


# virtual methods
.method public final a()Lt7/u0;
    .locals 1

    .line 1
    new-instance v0, Lj8/i;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lj8/i;-><init>(Lj8/h;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public final b(I)Lt7/t0;
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lt7/t0;->b(I)Lt7/t0;

    .line 2
    .line 3
    .line 4
    return-object p0
.end method

.method public final d()Lt7/t0;
    .locals 1

    .line 1
    const/4 v0, -0x3

    .line 2
    iput v0, p0, Lt7/t0;->r:I

    .line 3
    .line 4
    return-object p0
.end method

.method public final e(Lt7/r0;)Lt7/t0;
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lt7/t0;->e(Lt7/r0;)Lt7/t0;

    .line 2
    .line 3
    .line 4
    return-object p0
.end method

.method public final f()Lt7/t0;
    .locals 0

    .line 1
    invoke-super {p0}, Lt7/t0;->f()Lt7/t0;

    .line 2
    .line 3
    .line 4
    return-object p0
.end method

.method public final g([Ljava/lang/String;)Lt7/t0;
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lt7/t0;->g([Ljava/lang/String;)Lt7/t0;

    .line 2
    .line 3
    .line 4
    return-object p0
.end method

.method public final h()Lt7/t0;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lt7/t0;->q:Z

    .line 3
    .line 4
    return-object p0
.end method

.method public final i(IZ)Lt7/t0;
    .locals 0

    .line 1
    invoke-super {p0, p1, p2}, Lt7/t0;->i(IZ)Lt7/t0;

    .line 2
    .line 3
    .line 4
    return-object p0
.end method

.method public final j(Ljava/util/Set;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lt7/t0;->t:Ljava/util/HashSet;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/HashSet;->clear()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lt7/t0;->t:Ljava/util/HashSet;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    .line 9
    .line 10
    .line 11
    return-void
.end method
