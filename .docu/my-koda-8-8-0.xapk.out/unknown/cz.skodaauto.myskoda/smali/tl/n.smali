.class public final Ltl/n;
.super Ltl/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/graphics/drawable/Drawable;

.field public final b:Ltl/h;

.field public final c:Lkl/e;

.field public final d:Lrl/a;

.field public final e:Ljava/lang/String;

.field public final f:Z

.field public final g:Z


# direct methods
.method public constructor <init>(Landroid/graphics/drawable/Drawable;Ltl/h;Lkl/e;Lrl/a;Ljava/lang/String;ZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltl/n;->a:Landroid/graphics/drawable/Drawable;

    .line 5
    .line 6
    iput-object p2, p0, Ltl/n;->b:Ltl/h;

    .line 7
    .line 8
    iput-object p3, p0, Ltl/n;->c:Lkl/e;

    .line 9
    .line 10
    iput-object p4, p0, Ltl/n;->d:Lrl/a;

    .line 11
    .line 12
    iput-object p5, p0, Ltl/n;->e:Ljava/lang/String;

    .line 13
    .line 14
    iput-boolean p6, p0, Ltl/n;->f:Z

    .line 15
    .line 16
    iput-boolean p7, p0, Ltl/n;->g:Z

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a()Landroid/graphics/drawable/Drawable;
    .locals 0

    .line 1
    iget-object p0, p0, Ltl/n;->a:Landroid/graphics/drawable/Drawable;

    .line 2
    .line 3
    return-object p0
.end method

.method public final b()Ltl/h;
    .locals 0

    .line 1
    iget-object p0, p0, Ltl/n;->b:Ltl/h;

    .line 2
    .line 3
    return-object p0
.end method

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
    instance-of v1, p1, Ltl/n;

    .line 6
    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    check-cast p1, Ltl/n;

    .line 10
    .line 11
    iget-object v1, p1, Ltl/n;->a:Landroid/graphics/drawable/Drawable;

    .line 12
    .line 13
    iget-object v2, p0, Ltl/n;->a:Landroid/graphics/drawable/Drawable;

    .line 14
    .line 15
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_1

    .line 20
    .line 21
    iget-object v1, p0, Ltl/n;->b:Ltl/h;

    .line 22
    .line 23
    iget-object v2, p1, Ltl/n;->b:Ltl/h;

    .line 24
    .line 25
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_1

    .line 30
    .line 31
    iget-object v1, p0, Ltl/n;->c:Lkl/e;

    .line 32
    .line 33
    iget-object v2, p1, Ltl/n;->c:Lkl/e;

    .line 34
    .line 35
    if-ne v1, v2, :cond_1

    .line 36
    .line 37
    iget-object v1, p0, Ltl/n;->d:Lrl/a;

    .line 38
    .line 39
    iget-object v2, p1, Ltl/n;->d:Lrl/a;

    .line 40
    .line 41
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    if-eqz v1, :cond_1

    .line 46
    .line 47
    iget-object v1, p0, Ltl/n;->e:Ljava/lang/String;

    .line 48
    .line 49
    iget-object v2, p1, Ltl/n;->e:Ljava/lang/String;

    .line 50
    .line 51
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    if-eqz v1, :cond_1

    .line 56
    .line 57
    iget-boolean v1, p0, Ltl/n;->f:Z

    .line 58
    .line 59
    iget-boolean v2, p1, Ltl/n;->f:Z

    .line 60
    .line 61
    if-ne v1, v2, :cond_1

    .line 62
    .line 63
    iget-boolean p0, p0, Ltl/n;->g:Z

    .line 64
    .line 65
    iget-boolean p1, p1, Ltl/n;->g:Z

    .line 66
    .line 67
    if-ne p0, p1, :cond_1

    .line 68
    .line 69
    return v0

    .line 70
    :cond_1
    const/4 p0, 0x0

    .line 71
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Ltl/n;->a:Landroid/graphics/drawable/Drawable;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Ltl/n;->b:Ltl/h;

    .line 11
    .line 12
    invoke-virtual {v2}, Ltl/h;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    iget-object v0, p0, Ltl/n;->c:Lkl/e;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, v2

    .line 25
    mul-int/2addr v0, v1

    .line 26
    const/4 v2, 0x0

    .line 27
    iget-object v3, p0, Ltl/n;->d:Lrl/a;

    .line 28
    .line 29
    if-eqz v3, :cond_0

    .line 30
    .line 31
    invoke-virtual {v3}, Lrl/a;->hashCode()I

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    move v3, v2

    .line 37
    :goto_0
    add-int/2addr v0, v3

    .line 38
    mul-int/2addr v0, v1

    .line 39
    iget-object v3, p0, Ltl/n;->e:Ljava/lang/String;

    .line 40
    .line 41
    if-eqz v3, :cond_1

    .line 42
    .line 43
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    :cond_1
    add-int/2addr v0, v2

    .line 48
    mul-int/2addr v0, v1

    .line 49
    iget-boolean v2, p0, Ltl/n;->f:Z

    .line 50
    .line 51
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    iget-boolean p0, p0, Ltl/n;->g:Z

    .line 56
    .line 57
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    add-int/2addr p0, v0

    .line 62
    return p0
.end method
