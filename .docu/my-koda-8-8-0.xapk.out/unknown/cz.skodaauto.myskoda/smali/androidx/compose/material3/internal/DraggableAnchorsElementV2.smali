.class final Landroidx/compose/material3/internal/DraggableAnchorsElementV2;
.super Lv3/z0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Lv3/z0;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0010\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0002\u0018\u0000*\u0004\u0008\u0000\u0010\u00012\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00028\u00000\u00030\u0002\u00a8\u0006\u0004"
    }
    d2 = {
        "Landroidx/compose/material3/internal/DraggableAnchorsElementV2;",
        "T",
        "Lv3/z0;",
        "Li2/j0;",
        "material3"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final b:Lg1/q;

.field public final c:Lay0/n;


# direct methods
.method public constructor <init>(Lg1/q;Lay0/n;)V
    .locals 1

    .line 1
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Landroidx/compose/material3/internal/DraggableAnchorsElementV2;->b:Lg1/q;

    .line 7
    .line 8
    iput-object p2, p0, Landroidx/compose/material3/internal/DraggableAnchorsElementV2;->c:Lay0/n;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Landroidx/compose/material3/internal/DraggableAnchorsElementV2;

    .line 6
    .line 7
    if-nez v1, :cond_1

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_1
    check-cast p1, Landroidx/compose/material3/internal/DraggableAnchorsElementV2;

    .line 11
    .line 12
    iget-object v1, p1, Landroidx/compose/material3/internal/DraggableAnchorsElementV2;->b:Lg1/q;

    .line 13
    .line 14
    iget-object v2, p0, Landroidx/compose/material3/internal/DraggableAnchorsElementV2;->b:Lg1/q;

    .line 15
    .line 16
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-nez v1, :cond_2

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_2
    iget-object p0, p0, Landroidx/compose/material3/internal/DraggableAnchorsElementV2;->c:Lay0/n;

    .line 24
    .line 25
    iget-object p1, p1, Landroidx/compose/material3/internal/DraggableAnchorsElementV2;->c:Lay0/n;

    .line 26
    .line 27
    if-eq p0, p1, :cond_3

    .line 28
    .line 29
    :goto_0
    const/4 p0, 0x0

    .line 30
    return p0

    .line 31
    :cond_3
    sget-object p0, Lg1/w1;->d:Lg1/w1;

    .line 32
    .line 33
    return v0
.end method

.method public final h()Lx2/r;
    .locals 3

    .line 1
    new-instance v0, Li2/j0;

    .line 2
    .line 3
    sget-object v1, Lg1/w1;->e:Lg1/w1;

    .line 4
    .line 5
    invoke-direct {v0}, Lx2/r;-><init>()V

    .line 6
    .line 7
    .line 8
    iget-object v2, p0, Landroidx/compose/material3/internal/DraggableAnchorsElementV2;->b:Lg1/q;

    .line 9
    .line 10
    iput-object v2, v0, Li2/j0;->r:Lg1/q;

    .line 11
    .line 12
    iget-object p0, p0, Landroidx/compose/material3/internal/DraggableAnchorsElementV2;->c:Lay0/n;

    .line 13
    .line 14
    iput-object p0, v0, Li2/j0;->s:Lay0/n;

    .line 15
    .line 16
    iput-object v1, v0, Li2/j0;->t:Lg1/w1;

    .line 17
    .line 18
    return-object v0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Landroidx/compose/material3/internal/DraggableAnchorsElementV2;->b:Lg1/q;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object p0, p0, Landroidx/compose/material3/internal/DraggableAnchorsElementV2;->c:Lay0/n;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    mul-int/lit8 p0, p0, 0x1f

    .line 17
    .line 18
    sget-object v0, Lg1/w1;->e:Lg1/w1;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, p0

    .line 25
    return v0
.end method

.method public final j(Lx2/r;)V
    .locals 1

    .line 1
    check-cast p1, Li2/j0;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/compose/material3/internal/DraggableAnchorsElementV2;->b:Lg1/q;

    .line 4
    .line 5
    iput-object v0, p1, Li2/j0;->r:Lg1/q;

    .line 6
    .line 7
    iget-object p0, p0, Landroidx/compose/material3/internal/DraggableAnchorsElementV2;->c:Lay0/n;

    .line 8
    .line 9
    iput-object p0, p1, Li2/j0;->s:Lay0/n;

    .line 10
    .line 11
    sget-object p0, Lg1/w1;->e:Lg1/w1;

    .line 12
    .line 13
    iput-object p0, p1, Li2/j0;->t:Lg1/w1;

    .line 14
    .line 15
    return-void
.end method
