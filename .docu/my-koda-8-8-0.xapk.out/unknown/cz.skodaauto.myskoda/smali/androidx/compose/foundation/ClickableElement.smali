.class final Landroidx/compose/foundation/ClickableElement;
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
        "Landroidx/compose/foundation/ClickableElement;",
        "Lv3/z0;",
        "Le1/v;",
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
.field public final b:Li1/l;

.field public final c:Le1/s0;

.field public final d:Z

.field public final e:Z

.field public final f:Ljava/lang/String;

.field public final g:Ld4/i;

.field public final h:Lay0/a;


# direct methods
.method public constructor <init>(Li1/l;Le1/s0;ZZLjava/lang/String;Ld4/i;Lay0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/compose/foundation/ClickableElement;->b:Li1/l;

    .line 5
    .line 6
    iput-object p2, p0, Landroidx/compose/foundation/ClickableElement;->c:Le1/s0;

    .line 7
    .line 8
    iput-boolean p3, p0, Landroidx/compose/foundation/ClickableElement;->d:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Landroidx/compose/foundation/ClickableElement;->e:Z

    .line 11
    .line 12
    iput-object p5, p0, Landroidx/compose/foundation/ClickableElement;->f:Ljava/lang/String;

    .line 13
    .line 14
    iput-object p6, p0, Landroidx/compose/foundation/ClickableElement;->g:Ld4/i;

    .line 15
    .line 16
    iput-object p7, p0, Landroidx/compose/foundation/ClickableElement;->h:Lay0/a;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    if-nez p1, :cond_1

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_1
    const-class v0, Landroidx/compose/foundation/ClickableElement;

    .line 8
    .line 9
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    if-eq v0, v1, :cond_2

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_2
    check-cast p1, Landroidx/compose/foundation/ClickableElement;

    .line 17
    .line 18
    iget-object v0, p0, Landroidx/compose/foundation/ClickableElement;->b:Li1/l;

    .line 19
    .line 20
    iget-object v1, p1, Landroidx/compose/foundation/ClickableElement;->b:Li1/l;

    .line 21
    .line 22
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-nez v0, :cond_3

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_3
    iget-object v0, p0, Landroidx/compose/foundation/ClickableElement;->c:Le1/s0;

    .line 30
    .line 31
    iget-object v1, p1, Landroidx/compose/foundation/ClickableElement;->c:Le1/s0;

    .line 32
    .line 33
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-nez v0, :cond_4

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_4
    iget-boolean v0, p0, Landroidx/compose/foundation/ClickableElement;->d:Z

    .line 41
    .line 42
    iget-boolean v1, p1, Landroidx/compose/foundation/ClickableElement;->d:Z

    .line 43
    .line 44
    if-eq v0, v1, :cond_5

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_5
    iget-boolean v0, p0, Landroidx/compose/foundation/ClickableElement;->e:Z

    .line 48
    .line 49
    iget-boolean v1, p1, Landroidx/compose/foundation/ClickableElement;->e:Z

    .line 50
    .line 51
    if-eq v0, v1, :cond_6

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_6
    iget-object v0, p0, Landroidx/compose/foundation/ClickableElement;->f:Ljava/lang/String;

    .line 55
    .line 56
    iget-object v1, p1, Landroidx/compose/foundation/ClickableElement;->f:Ljava/lang/String;

    .line 57
    .line 58
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    if-nez v0, :cond_7

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_7
    iget-object v0, p0, Landroidx/compose/foundation/ClickableElement;->g:Ld4/i;

    .line 66
    .line 67
    iget-object v1, p1, Landroidx/compose/foundation/ClickableElement;->g:Ld4/i;

    .line 68
    .line 69
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-nez v0, :cond_8

    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_8
    iget-object p0, p0, Landroidx/compose/foundation/ClickableElement;->h:Lay0/a;

    .line 77
    .line 78
    iget-object p1, p1, Landroidx/compose/foundation/ClickableElement;->h:Lay0/a;

    .line 79
    .line 80
    if-eq p0, p1, :cond_9

    .line 81
    .line 82
    :goto_0
    const/4 p0, 0x0

    .line 83
    return p0

    .line 84
    :cond_9
    :goto_1
    const/4 p0, 0x1

    .line 85
    return p0
.end method

.method public final h()Lx2/r;
    .locals 8

    .line 1
    new-instance v0, Le1/v;

    .line 2
    .line 3
    iget-object v6, p0, Landroidx/compose/foundation/ClickableElement;->g:Ld4/i;

    .line 4
    .line 5
    iget-object v7, p0, Landroidx/compose/foundation/ClickableElement;->h:Lay0/a;

    .line 6
    .line 7
    iget-object v1, p0, Landroidx/compose/foundation/ClickableElement;->b:Li1/l;

    .line 8
    .line 9
    iget-object v2, p0, Landroidx/compose/foundation/ClickableElement;->c:Le1/s0;

    .line 10
    .line 11
    iget-boolean v3, p0, Landroidx/compose/foundation/ClickableElement;->d:Z

    .line 12
    .line 13
    iget-boolean v4, p0, Landroidx/compose/foundation/ClickableElement;->e:Z

    .line 14
    .line 15
    iget-object v5, p0, Landroidx/compose/foundation/ClickableElement;->f:Ljava/lang/String;

    .line 16
    .line 17
    invoke-direct/range {v0 .. v7}, Le1/h;-><init>(Li1/l;Le1/s0;ZZLjava/lang/String;Ld4/i;Lay0/a;)V

    .line 18
    .line 19
    .line 20
    return-object v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Landroidx/compose/foundation/ClickableElement;->b:Li1/l;

    .line 3
    .line 4
    if-eqz v1, :cond_0

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v1, v0

    .line 12
    :goto_0
    const/16 v2, 0x1f

    .line 13
    .line 14
    mul-int/2addr v1, v2

    .line 15
    iget-object v3, p0, Landroidx/compose/foundation/ClickableElement;->c:Le1/s0;

    .line 16
    .line 17
    if-eqz v3, :cond_1

    .line 18
    .line 19
    invoke-interface {v3}, Le1/s0;->hashCode()I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move v3, v0

    .line 25
    :goto_1
    add-int/2addr v1, v3

    .line 26
    mul-int/2addr v1, v2

    .line 27
    iget-boolean v3, p0, Landroidx/compose/foundation/ClickableElement;->d:Z

    .line 28
    .line 29
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    iget-boolean v3, p0, Landroidx/compose/foundation/ClickableElement;->e:Z

    .line 34
    .line 35
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    iget-object v3, p0, Landroidx/compose/foundation/ClickableElement;->f:Ljava/lang/String;

    .line 40
    .line 41
    if-eqz v3, :cond_2

    .line 42
    .line 43
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    goto :goto_2

    .line 48
    :cond_2
    move v3, v0

    .line 49
    :goto_2
    add-int/2addr v1, v3

    .line 50
    mul-int/2addr v1, v2

    .line 51
    iget-object v3, p0, Landroidx/compose/foundation/ClickableElement;->g:Ld4/i;

    .line 52
    .line 53
    if-eqz v3, :cond_3

    .line 54
    .line 55
    iget v0, v3, Ld4/i;->a:I

    .line 56
    .line 57
    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    :cond_3
    add-int/2addr v1, v0

    .line 62
    mul-int/2addr v1, v2

    .line 63
    iget-object p0, p0, Landroidx/compose/foundation/ClickableElement;->h:Lay0/a;

    .line 64
    .line 65
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    add-int/2addr p0, v1

    .line 70
    return p0
.end method

.method public final j(Lx2/r;)V
    .locals 8

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Le1/v;

    .line 3
    .line 4
    iget-object v6, p0, Landroidx/compose/foundation/ClickableElement;->g:Ld4/i;

    .line 5
    .line 6
    iget-object v7, p0, Landroidx/compose/foundation/ClickableElement;->h:Lay0/a;

    .line 7
    .line 8
    iget-object v1, p0, Landroidx/compose/foundation/ClickableElement;->b:Li1/l;

    .line 9
    .line 10
    iget-object v2, p0, Landroidx/compose/foundation/ClickableElement;->c:Le1/s0;

    .line 11
    .line 12
    iget-boolean v3, p0, Landroidx/compose/foundation/ClickableElement;->d:Z

    .line 13
    .line 14
    iget-boolean v4, p0, Landroidx/compose/foundation/ClickableElement;->e:Z

    .line 15
    .line 16
    iget-object v5, p0, Landroidx/compose/foundation/ClickableElement;->f:Ljava/lang/String;

    .line 17
    .line 18
    invoke-virtual/range {v0 .. v7}, Le1/h;->j1(Li1/l;Le1/s0;ZZLjava/lang/String;Ld4/i;Lay0/a;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method
