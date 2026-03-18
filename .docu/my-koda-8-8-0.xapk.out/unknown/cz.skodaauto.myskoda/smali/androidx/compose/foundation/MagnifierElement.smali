.class public final Landroidx/compose/foundation/MagnifierElement;
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
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0001\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Landroidx/compose/foundation/MagnifierElement;",
        "Lv3/z0;",
        "Le1/u0;",
        "foundation_release"
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
.field public final b:Laj0/c;

.field public final c:Le2/b1;

.field public final d:Le1/f1;


# direct methods
.method public constructor <init>(Laj0/c;Le2/b1;Le1/f1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/compose/foundation/MagnifierElement;->b:Laj0/c;

    .line 5
    .line 6
    iput-object p2, p0, Landroidx/compose/foundation/MagnifierElement;->c:Le2/b1;

    .line 7
    .line 8
    iput-object p3, p0, Landroidx/compose/foundation/MagnifierElement;->d:Le1/f1;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    const/4 p0, 0x0

    .line 6
    return p0
.end method

.method public final h()Lx2/r;
    .locals 3

    .line 1
    new-instance v0, Le1/u0;

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/compose/foundation/MagnifierElement;->b:Laj0/c;

    .line 4
    .line 5
    iget-object v2, p0, Landroidx/compose/foundation/MagnifierElement;->c:Le2/b1;

    .line 6
    .line 7
    iget-object p0, p0, Landroidx/compose/foundation/MagnifierElement;->d:Le1/f1;

    .line 8
    .line 9
    invoke-direct {v0, v1, v2, p0}, Le1/u0;-><init>(Laj0/c;Le2/b1;Le1/f1;)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public final hashCode()I
    .locals 6

    .line 1
    iget-object v0, p0, Landroidx/compose/foundation/MagnifierElement;->b:Laj0/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit16 v0, v0, 0x3c1

    .line 8
    .line 9
    const/high16 v1, 0x7fc00000    # Float.NaN

    .line 10
    .line 11
    const/16 v2, 0x1f

    .line 12
    .line 13
    invoke-static {v1, v0, v2}, La7/g0;->c(FII)I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v3, 0x1

    .line 18
    invoke-static {v0, v2, v3}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    const-wide v4, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    invoke-static {v4, v5, v0, v2}, La7/g0;->f(JII)I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    invoke-static {v1, v0, v2}, La7/g0;->c(FII)I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    invoke-static {v1, v0, v2}, La7/g0;->c(FII)I

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    invoke-static {v0, v2, v3}, La7/g0;->e(IIZ)I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    iget-object v1, p0, Landroidx/compose/foundation/MagnifierElement;->c:Le2/b1;

    .line 44
    .line 45
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    add-int/2addr v1, v0

    .line 50
    mul-int/2addr v1, v2

    .line 51
    iget-object p0, p0, Landroidx/compose/foundation/MagnifierElement;->d:Le1/f1;

    .line 52
    .line 53
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    add-int/2addr p0, v1

    .line 58
    return p0
.end method

.method public final j(Lx2/r;)V
    .locals 8

    .line 1
    check-cast p1, Le1/u0;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object v0, p1, Le1/u0;->t:Le1/f1;

    .line 7
    .line 8
    iget-object v1, p1, Le1/u0;->u:Landroid/view/View;

    .line 9
    .line 10
    iget-object v2, p1, Le1/u0;->v:Lt4/c;

    .line 11
    .line 12
    iget-object v3, p0, Landroidx/compose/foundation/MagnifierElement;->b:Laj0/c;

    .line 13
    .line 14
    iput-object v3, p1, Le1/u0;->r:Laj0/c;

    .line 15
    .line 16
    iget-object v3, p0, Landroidx/compose/foundation/MagnifierElement;->c:Le2/b1;

    .line 17
    .line 18
    iput-object v3, p1, Le1/u0;->s:Le2/b1;

    .line 19
    .line 20
    iget-object p0, p0, Landroidx/compose/foundation/MagnifierElement;->d:Le1/f1;

    .line 21
    .line 22
    iput-object p0, p1, Le1/u0;->t:Le1/f1;

    .line 23
    .line 24
    invoke-static {p1}, Lv3/f;->z(Lv3/m;)Landroid/view/View;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    invoke-static {p1}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 29
    .line 30
    .line 31
    move-result-object v4

    .line 32
    iget-object v4, v4, Lv3/h0;->A:Lt4/c;

    .line 33
    .line 34
    iget-object v5, p1, Le1/u0;->w:Lbu/c;

    .line 35
    .line 36
    if-eqz v5, :cond_2

    .line 37
    .line 38
    sget-object v5, Le1/v0;->a:Ld4/z;

    .line 39
    .line 40
    const/high16 v5, 0x7fc00000    # Float.NaN

    .line 41
    .line 42
    invoke-static {v5}, Ljava/lang/Float;->isNaN(F)Z

    .line 43
    .line 44
    .line 45
    move-result v6

    .line 46
    if-eqz v6, :cond_0

    .line 47
    .line 48
    invoke-static {v5}, Ljava/lang/Float;->isNaN(F)Z

    .line 49
    .line 50
    .line 51
    move-result v6

    .line 52
    if-eqz v6, :cond_0

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 56
    .line 57
    .line 58
    :goto_0
    const-wide v6, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 59
    .line 60
    .line 61
    .line 62
    .line 63
    invoke-static {v6, v7, v6, v7}, Lt4/h;->a(JJ)Z

    .line 64
    .line 65
    .line 66
    move-result v6

    .line 67
    if-eqz v6, :cond_1

    .line 68
    .line 69
    invoke-static {v5, v5}, Lt4/f;->a(FF)Z

    .line 70
    .line 71
    .line 72
    move-result v6

    .line 73
    if-eqz v6, :cond_1

    .line 74
    .line 75
    invoke-static {v5, v5}, Lt4/f;->a(FF)Z

    .line 76
    .line 77
    .line 78
    move-result v5

    .line 79
    if-eqz v5, :cond_1

    .line 80
    .line 81
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result p0

    .line 85
    if-eqz p0, :cond_1

    .line 86
    .line 87
    invoke-virtual {v3, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result p0

    .line 91
    if-eqz p0, :cond_1

    .line 92
    .line 93
    invoke-static {v4, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result p0

    .line 97
    if-nez p0, :cond_2

    .line 98
    .line 99
    :cond_1
    invoke-virtual {p1}, Le1/u0;->Y0()V

    .line 100
    .line 101
    .line 102
    :cond_2
    invoke-virtual {p1}, Le1/u0;->Z0()V

    .line 103
    .line 104
    .line 105
    return-void
.end method
