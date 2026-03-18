.class public final Ltd/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Z

.field public final c:Ljava/util/List;

.field public final d:Z

.field public final e:Ljava/lang/String;

.field public final f:Ljava/util/List;

.field public final g:Z


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;ZLjava/util/List;ZLjava/lang/String;Ljava/util/List;I)V
    .locals 8

    and-int/lit8 p7, p7, 0x8

    if-eqz p7, :cond_0

    const/4 p4, 0x0

    :cond_0
    move v4, p4

    const/4 v7, 0x0

    move-object v0, p0

    move-object v1, p1

    move v2, p2

    move-object v3, p3

    move-object v5, p5

    move-object v6, p6

    .line 1
    invoke-direct/range {v0 .. v7}, Ltd/p;-><init>(Ljava/lang/String;ZLjava/util/List;ZLjava/lang/String;Ljava/util/List;Z)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ZLjava/util/List;ZLjava/lang/String;Ljava/util/List;Z)V
    .locals 1

    const-string v0, "items"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "datePickerLabel"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "filters"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Ltd/p;->a:Ljava/lang/String;

    .line 4
    iput-boolean p2, p0, Ltd/p;->b:Z

    .line 5
    iput-object p3, p0, Ltd/p;->c:Ljava/util/List;

    .line 6
    iput-boolean p4, p0, Ltd/p;->d:Z

    .line 7
    iput-object p5, p0, Ltd/p;->e:Ljava/lang/String;

    .line 8
    iput-object p6, p0, Ltd/p;->f:Ljava/util/List;

    .line 9
    iput-boolean p7, p0, Ltd/p;->g:Z

    return-void
.end method

.method public static a(Ltd/p;Ljava/util/List;I)Ltd/p;
    .locals 8

    .line 1
    iget-object v1, p0, Ltd/p;->a:Ljava/lang/String;

    .line 2
    .line 3
    iget-boolean v2, p0, Ltd/p;->b:Z

    .line 4
    .line 5
    iget-object v3, p0, Ltd/p;->c:Ljava/util/List;

    .line 6
    .line 7
    iget-boolean v4, p0, Ltd/p;->d:Z

    .line 8
    .line 9
    iget-object v5, p0, Ltd/p;->e:Ljava/lang/String;

    .line 10
    .line 11
    and-int/lit8 v0, p2, 0x20

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    iget-object p1, p0, Ltd/p;->f:Ljava/util/List;

    .line 16
    .line 17
    :cond_0
    move-object v6, p1

    .line 18
    and-int/lit8 p1, p2, 0x40

    .line 19
    .line 20
    if-eqz p1, :cond_1

    .line 21
    .line 22
    iget-boolean p1, p0, Ltd/p;->g:Z

    .line 23
    .line 24
    :goto_0
    move v7, p1

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    const/4 p1, 0x1

    .line 27
    goto :goto_0

    .line 28
    :goto_1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    const-string p0, "items"

    .line 32
    .line 33
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const-string p0, "datePickerLabel"

    .line 37
    .line 38
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    const-string p0, "filters"

    .line 42
    .line 43
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    new-instance v0, Ltd/p;

    .line 47
    .line 48
    invoke-direct/range {v0 .. v7}, Ltd/p;-><init>(Ljava/lang/String;ZLjava/util/List;ZLjava/lang/String;Ljava/util/List;Z)V

    .line 49
    .line 50
    .line 51
    return-object v0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ltd/p;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Ltd/p;

    .line 12
    .line 13
    iget-object v1, p0, Ltd/p;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Ltd/p;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-boolean v1, p0, Ltd/p;->b:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Ltd/p;->b:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Ltd/p;->c:Ljava/util/List;

    .line 32
    .line 33
    iget-object v3, p1, Ltd/p;->c:Ljava/util/List;

    .line 34
    .line 35
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-nez v1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-boolean v1, p0, Ltd/p;->d:Z

    .line 43
    .line 44
    iget-boolean v3, p1, Ltd/p;->d:Z

    .line 45
    .line 46
    if-eq v1, v3, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget-object v1, p0, Ltd/p;->e:Ljava/lang/String;

    .line 50
    .line 51
    iget-object v3, p1, Ltd/p;->e:Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    if-nez v1, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    iget-object v1, p0, Ltd/p;->f:Ljava/util/List;

    .line 61
    .line 62
    iget-object v3, p1, Ltd/p;->f:Ljava/util/List;

    .line 63
    .line 64
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    if-nez v1, :cond_7

    .line 69
    .line 70
    return v2

    .line 71
    :cond_7
    iget-boolean p0, p0, Ltd/p;->g:Z

    .line 72
    .line 73
    iget-boolean p1, p1, Ltd/p;->g:Z

    .line 74
    .line 75
    if-eq p0, p1, :cond_8

    .line 76
    .line 77
    return v2

    .line 78
    :cond_8
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Ltd/p;->a:Ljava/lang/String;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    :goto_0
    const/16 v1, 0x1f

    .line 12
    .line 13
    mul-int/2addr v0, v1

    .line 14
    iget-boolean v2, p0, Ltd/p;->b:Z

    .line 15
    .line 16
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    iget-object v2, p0, Ltd/p;->c:Ljava/util/List;

    .line 21
    .line 22
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    iget-boolean v2, p0, Ltd/p;->d:Z

    .line 27
    .line 28
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    iget-object v2, p0, Ltd/p;->e:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    iget-object v2, p0, Ltd/p;->f:Ljava/util/List;

    .line 39
    .line 40
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    iget-boolean p0, p0, Ltd/p;->g:Z

    .line 45
    .line 46
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    add-int/2addr p0, v0

    .line 51
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", showDisclaimer="

    .line 2
    .line 3
    const-string v1, ", items="

    .line 4
    .line 5
    const-string v2, "ChargingStatisticsOverviewUiState(disclaimer="

    .line 6
    .line 7
    iget-object v3, p0, Ltd/p;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-boolean v4, p0, Ltd/p;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v1, v4}, Lia/b;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isDatePicker="

    .line 16
    .line 17
    const-string v2, ", datePickerLabel="

    .line 18
    .line 19
    iget-object v3, p0, Ltd/p;->c:Ljava/util/List;

    .line 20
    .line 21
    iget-boolean v4, p0, Ltd/p;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->w(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", filters="

    .line 27
    .line 28
    const-string v2, ", isReloading="

    .line 29
    .line 30
    iget-object v3, p0, Ltd/p;->e:Ljava/lang/String;

    .line 31
    .line 32
    iget-object v4, p0, Ltd/p;->f:Ljava/util/List;

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, Lu/w;->m(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string v1, ")"

    .line 38
    .line 39
    iget-boolean p0, p0, Ltd/p;->g:Z

    .line 40
    .line 41
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0
.end method
