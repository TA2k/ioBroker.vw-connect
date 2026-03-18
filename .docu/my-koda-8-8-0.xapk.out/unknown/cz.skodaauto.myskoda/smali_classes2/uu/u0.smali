.class public final Luu/u0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Z

.field public final b:Lsp/j;

.field public final c:Luu/z0;

.field public final d:F

.field public final e:F


# direct methods
.method public synthetic constructor <init>(Lsp/j;I)V
    .locals 6

    and-int/lit8 p2, p2, 0x20

    if-eqz p2, :cond_0

    const/4 p1, 0x0

    :cond_0
    move-object v2, p1

    .line 7
    sget-object v3, Luu/z0;->e:Luu/z0;

    const/high16 v4, 0x41a80000    # 21.0f

    const/high16 v5, 0x40400000    # 3.0f

    const/4 v1, 0x0

    move-object v0, p0

    .line 8
    invoke-direct/range {v0 .. v5}, Luu/u0;-><init>(ZLsp/j;Luu/z0;FF)V

    return-void
.end method

.method public constructor <init>(ZLsp/j;Luu/z0;FF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-boolean p1, p0, Luu/u0;->a:Z

    .line 3
    iput-object p2, p0, Luu/u0;->b:Lsp/j;

    .line 4
    iput-object p3, p0, Luu/u0;->c:Luu/z0;

    .line 5
    iput p4, p0, Luu/u0;->d:F

    .line 6
    iput p5, p0, Luu/u0;->e:F

    return-void
.end method

.method public static a(Luu/u0;ZLuu/z0;I)Luu/u0;
    .locals 6

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 5
    .line 6
    .line 7
    and-int/lit8 v0, p3, 0x4

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-boolean p1, p0, Luu/u0;->a:Z

    .line 12
    .line 13
    :cond_0
    move v1, p1

    .line 14
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    iget-object v2, p0, Luu/u0;->b:Lsp/j;

    .line 21
    .line 22
    and-int/lit8 p1, p3, 0x40

    .line 23
    .line 24
    if-eqz p1, :cond_1

    .line 25
    .line 26
    iget-object p2, p0, Luu/u0;->c:Luu/z0;

    .line 27
    .line 28
    :cond_1
    move-object v3, p2

    .line 29
    iget v4, p0, Luu/u0;->d:F

    .line 30
    .line 31
    iget v5, p0, Luu/u0;->e:F

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 34
    .line 35
    .line 36
    const-string p0, "mapType"

    .line 37
    .line 38
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    new-instance v0, Luu/u0;

    .line 42
    .line 43
    invoke-direct/range {v0 .. v5}, Luu/u0;-><init>(ZLsp/j;Luu/z0;FF)V

    .line 44
    .line 45
    .line 46
    return-object v0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Luu/u0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Luu/u0;

    .line 6
    .line 7
    iget-boolean v0, p0, Luu/u0;->a:Z

    .line 8
    .line 9
    iget-boolean v1, p1, Luu/u0;->a:Z

    .line 10
    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    iget-object v0, p0, Luu/u0;->b:Lsp/j;

    .line 14
    .line 15
    iget-object v1, p1, Luu/u0;->b:Lsp/j;

    .line 16
    .line 17
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    iget-object v0, p0, Luu/u0;->c:Luu/z0;

    .line 24
    .line 25
    iget-object v1, p1, Luu/u0;->c:Luu/z0;

    .line 26
    .line 27
    if-ne v0, v1, :cond_0

    .line 28
    .line 29
    iget v0, p0, Luu/u0;->d:F

    .line 30
    .line 31
    iget v1, p1, Luu/u0;->d:F

    .line 32
    .line 33
    cmpg-float v0, v0, v1

    .line 34
    .line 35
    if-nez v0, :cond_0

    .line 36
    .line 37
    iget p0, p0, Luu/u0;->e:F

    .line 38
    .line 39
    iget p1, p1, Luu/u0;->e:F

    .line 40
    .line 41
    cmpg-float p0, p0, p1

    .line 42
    .line 43
    if-nez p0, :cond_0

    .line 44
    .line 45
    const/4 p0, 0x1

    .line 46
    return p0

    .line 47
    :cond_0
    const/4 p0, 0x0

    .line 48
    return p0
.end method

.method public final hashCode()I
    .locals 9

    .line 1
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 2
    .line 3
    iget-boolean v1, p0, Luu/u0;->a:Z

    .line 4
    .line 5
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    iget v1, p0, Luu/u0;->d:F

    .line 10
    .line 11
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 12
    .line 13
    .line 14
    move-result-object v7

    .line 15
    iget v1, p0, Luu/u0;->e:F

    .line 16
    .line 17
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 18
    .line 19
    .line 20
    move-result-object v8

    .line 21
    const/4 v4, 0x0

    .line 22
    iget-object v5, p0, Luu/u0;->b:Lsp/j;

    .line 23
    .line 24
    iget-object v6, p0, Luu/u0;->c:Luu/z0;

    .line 25
    .line 26
    move-object v1, v0

    .line 27
    move-object v3, v0

    .line 28
    filled-new-array/range {v0 .. v8}, [Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-static {p0}, Ljava/util/Objects;->hash([Ljava/lang/Object;)I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MapProperties(isBuildingEnabled=false, isIndoorEnabled=false, isMyLocationEnabled="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-boolean v1, p0, Luu/u0;->a:Z

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", isTrafficEnabled=false, latLngBoundsForCameraTarget=null, mapStyleOptions="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Luu/u0;->b:Lsp/j;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", mapType="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Luu/u0;->c:Luu/z0;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", maxZoomPreference="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget v1, p0, Luu/u0;->d:F

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", minZoomPreference="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget p0, p0, Luu/u0;->e:F

    .line 49
    .line 50
    const/16 v1, 0x29

    .line 51
    .line 52
    invoke-static {v0, p0, v1}, La7/g0;->i(Ljava/lang/StringBuilder;FC)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method
