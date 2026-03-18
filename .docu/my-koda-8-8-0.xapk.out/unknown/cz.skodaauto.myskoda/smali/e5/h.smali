.class public Le5/h;
.super Le5/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lf5/d;


# instance fields
.field public final k0:Lz4/q;

.field public final l0:I

.field public final m0:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Lz4/q;I)V
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Le5/b;-><init>(Lz4/q;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Le5/h;->m0:Ljava/util/ArrayList;

    .line 10
    .line 11
    iput-object p1, p0, Le5/h;->k0:Lz4/q;

    .line 12
    .line 13
    iput p2, p0, Le5/h;->l0:I

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public apply()V
    .locals 0

    .line 1
    return-void
.end method

.method public final b()Lh5/d;
    .locals 0

    .line 1
    invoke-virtual {p0}, Le5/h;->s()Lh5/i;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final varargs q([Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Le5/h;->m0:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-static {p0, p1}, Ljava/util/Collections;->addAll(Ljava/util/Collection;[Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final r()V
    .locals 0

    .line 1
    invoke-super {p0}, Le5/b;->apply()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public s()Lh5/i;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method
