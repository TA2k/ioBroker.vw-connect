.class final Landroidx/compose/ui/input/nestedscroll/NestedScrollElement;
.super Lv3/z0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lv3/z0;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Landroidx/compose/ui/input/nestedscroll/NestedScrollElement;",
        "Lv3/z0;",
        "Lo3/g;",
        "ui_release"
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
.field public final b:Lo3/a;

.field public final c:Lo3/d;


# direct methods
.method public constructor <init>(Lo3/a;Lo3/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/compose/ui/input/nestedscroll/NestedScrollElement;->b:Lo3/a;

    .line 5
    .line 6
    iput-object p2, p0, Landroidx/compose/ui/input/nestedscroll/NestedScrollElement;->c:Lo3/d;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    instance-of v0, p1, Landroidx/compose/ui/input/nestedscroll/NestedScrollElement;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    check-cast p1, Landroidx/compose/ui/input/nestedscroll/NestedScrollElement;

    .line 8
    .line 9
    iget-object v0, p1, Landroidx/compose/ui/input/nestedscroll/NestedScrollElement;->b:Lo3/a;

    .line 10
    .line 11
    iget-object v2, p0, Landroidx/compose/ui/input/nestedscroll/NestedScrollElement;->b:Lo3/a;

    .line 12
    .line 13
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    return v1

    .line 20
    :cond_1
    iget-object p1, p1, Landroidx/compose/ui/input/nestedscroll/NestedScrollElement;->c:Lo3/d;

    .line 21
    .line 22
    iget-object p0, p0, Landroidx/compose/ui/input/nestedscroll/NestedScrollElement;->c:Lo3/d;

    .line 23
    .line 24
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    if-nez p0, :cond_2

    .line 29
    .line 30
    return v1

    .line 31
    :cond_2
    const/4 p0, 0x1

    .line 32
    return p0
.end method

.method public final h()Lx2/r;
    .locals 2

    .line 1
    new-instance v0, Lo3/g;

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/compose/ui/input/nestedscroll/NestedScrollElement;->b:Lo3/a;

    .line 4
    .line 5
    iget-object p0, p0, Landroidx/compose/ui/input/nestedscroll/NestedScrollElement;->c:Lo3/d;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0}, Lo3/g;-><init>(Lo3/a;Lo3/d;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Landroidx/compose/ui/input/nestedscroll/NestedScrollElement;->b:Lo3/a;

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
    iget-object p0, p0, Landroidx/compose/ui/input/nestedscroll/NestedScrollElement;->c:Lo3/d;

    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    :goto_0
    add-int/2addr v0, p0

    .line 20
    return v0
.end method

.method public final j(Lx2/r;)V
    .locals 3

    .line 1
    check-cast p1, Lo3/g;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/compose/ui/input/nestedscroll/NestedScrollElement;->b:Lo3/a;

    .line 4
    .line 5
    iput-object v0, p1, Lo3/g;->r:Lo3/a;

    .line 6
    .line 7
    iget-object v0, p1, Lo3/g;->s:Lo3/d;

    .line 8
    .line 9
    iget-object v1, v0, Lo3/d;->a:Lo3/g;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    if-ne v1, p1, :cond_0

    .line 13
    .line 14
    iput-object v2, v0, Lo3/d;->a:Lo3/g;

    .line 15
    .line 16
    :cond_0
    iget-object p0, p0, Landroidx/compose/ui/input/nestedscroll/NestedScrollElement;->c:Lo3/d;

    .line 17
    .line 18
    if-nez p0, :cond_1

    .line 19
    .line 20
    new-instance p0, Lo3/d;

    .line 21
    .line 22
    invoke-direct {p0}, Lo3/d;-><init>()V

    .line 23
    .line 24
    .line 25
    iput-object p0, p1, Lo3/g;->s:Lo3/d;

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-nez v0, :cond_2

    .line 33
    .line 34
    iput-object p0, p1, Lo3/g;->s:Lo3/d;

    .line 35
    .line 36
    :cond_2
    :goto_0
    iget-boolean p0, p1, Lx2/r;->q:Z

    .line 37
    .line 38
    if-eqz p0, :cond_3

    .line 39
    .line 40
    iget-object p0, p1, Lo3/g;->s:Lo3/d;

    .line 41
    .line 42
    iput-object p1, p0, Lo3/d;->a:Lo3/g;

    .line 43
    .line 44
    iput-object v2, p0, Lo3/d;->b:Lo3/g;

    .line 45
    .line 46
    iput-object v2, p1, Lo3/g;->t:Lo3/g;

    .line 47
    .line 48
    new-instance v0, La7/j;

    .line 49
    .line 50
    const/16 v1, 0x11

    .line 51
    .line 52
    invoke-direct {v0, p1, v1}, La7/j;-><init>(Ljava/lang/Object;I)V

    .line 53
    .line 54
    .line 55
    iput-object v0, p0, Lo3/d;->c:Lkotlin/jvm/internal/n;

    .line 56
    .line 57
    invoke-virtual {p1}, Lx2/r;->L0()Lvy0/b0;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    iput-object p1, p0, Lo3/d;->d:Lvy0/b0;

    .line 62
    .line 63
    :cond_3
    return-void
.end method
