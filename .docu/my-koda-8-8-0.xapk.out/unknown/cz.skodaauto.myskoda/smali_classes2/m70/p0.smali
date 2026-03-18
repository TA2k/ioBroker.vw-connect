.class public final Lm70/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Llf0/i;

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Lqr0/s;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Llf0/i;I)V
    .locals 9

    and-int/lit8 v0, p2, 0x1

    if-eqz v0, :cond_0

    .line 10
    sget-object p1, Llf0/i;->j:Llf0/i;

    :cond_0
    move-object v1, p1

    and-int/lit8 p1, p2, 0x2

    const/4 v0, 0x0

    const/4 v2, 0x1

    if-eqz p1, :cond_1

    move p1, v2

    goto :goto_0

    :cond_1
    move p1, v2

    move v2, v0

    :goto_0
    and-int/lit8 v3, p2, 0x4

    if-eqz v3, :cond_2

    move v3, v0

    goto :goto_1

    :cond_2
    move v3, p1

    :goto_1
    and-int/lit8 v4, p2, 0x8

    if-eqz v4, :cond_3

    move v4, v0

    goto :goto_2

    :cond_3
    move v4, p1

    .line 11
    :goto_2
    sget-object v5, Lqr0/s;->d:Lqr0/s;

    and-int/lit8 p1, p2, 0x20

    if-eqz p1, :cond_4

    .line 12
    const-string p1, ""

    :goto_3
    move-object v6, p1

    goto :goto_4

    .line 13
    :cond_4
    const-string p1, "12345 km"

    goto :goto_3

    :goto_4
    and-int/lit8 p1, p2, 0x40

    const/4 v0, 0x0

    if-eqz p1, :cond_5

    move-object v7, v0

    goto :goto_5

    :cond_5
    const-string p1, "5.6 l"

    move-object v7, p1

    :goto_5
    and-int/lit16 p1, p2, 0x80

    if-eqz p1, :cond_6

    :goto_6
    move-object v8, v0

    move-object v0, p0

    goto :goto_7

    :cond_6
    const-string v0, "5.4 kg"

    goto :goto_6

    :goto_7
    invoke-direct/range {v0 .. v8}, Lm70/p0;-><init>(Llf0/i;ZZZLqr0/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Llf0/i;ZZZLqr0/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    const-string v0, "viewMode"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "endMileage"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lm70/p0;->a:Llf0/i;

    .line 3
    iput-boolean p2, p0, Lm70/p0;->b:Z

    .line 4
    iput-boolean p3, p0, Lm70/p0;->c:Z

    .line 5
    iput-boolean p4, p0, Lm70/p0;->d:Z

    .line 6
    iput-object p5, p0, Lm70/p0;->e:Lqr0/s;

    .line 7
    iput-object p6, p0, Lm70/p0;->f:Ljava/lang/String;

    .line 8
    iput-object p7, p0, Lm70/p0;->g:Ljava/lang/String;

    .line 9
    iput-object p8, p0, Lm70/p0;->h:Ljava/lang/String;

    return-void
.end method

.method public static a(Lm70/p0;Llf0/i;ZZZLqr0/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lm70/p0;
    .locals 9

    .line 1
    move/from16 v0, p9

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Lm70/p0;->a:Llf0/i;

    .line 8
    .line 9
    :cond_0
    move-object v1, p1

    .line 10
    and-int/lit8 p1, v0, 0x4

    .line 11
    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    iget-boolean p3, p0, Lm70/p0;->c:Z

    .line 15
    .line 16
    :cond_1
    move v3, p3

    .line 17
    and-int/lit8 p1, v0, 0x8

    .line 18
    .line 19
    if-eqz p1, :cond_2

    .line 20
    .line 21
    iget-boolean p1, p0, Lm70/p0;->d:Z

    .line 22
    .line 23
    move v4, p1

    .line 24
    goto :goto_0

    .line 25
    :cond_2
    move v4, p4

    .line 26
    :goto_0
    and-int/lit8 p1, v0, 0x10

    .line 27
    .line 28
    if-eqz p1, :cond_3

    .line 29
    .line 30
    iget-object p1, p0, Lm70/p0;->e:Lqr0/s;

    .line 31
    .line 32
    move-object v5, p1

    .line 33
    goto :goto_1

    .line 34
    :cond_3
    move-object v5, p5

    .line 35
    :goto_1
    and-int/lit8 p1, v0, 0x20

    .line 36
    .line 37
    if-eqz p1, :cond_4

    .line 38
    .line 39
    iget-object p1, p0, Lm70/p0;->f:Ljava/lang/String;

    .line 40
    .line 41
    move-object v6, p1

    .line 42
    goto :goto_2

    .line 43
    :cond_4
    move-object v6, p6

    .line 44
    :goto_2
    and-int/lit8 p1, v0, 0x40

    .line 45
    .line 46
    if-eqz p1, :cond_5

    .line 47
    .line 48
    iget-object p1, p0, Lm70/p0;->g:Ljava/lang/String;

    .line 49
    .line 50
    move-object v7, p1

    .line 51
    goto :goto_3

    .line 52
    :cond_5
    move-object/from16 v7, p7

    .line 53
    .line 54
    :goto_3
    and-int/lit16 p1, v0, 0x80

    .line 55
    .line 56
    if-eqz p1, :cond_6

    .line 57
    .line 58
    iget-object p1, p0, Lm70/p0;->h:Ljava/lang/String;

    .line 59
    .line 60
    move-object v8, p1

    .line 61
    goto :goto_4

    .line 62
    :cond_6
    move-object/from16 v8, p8

    .line 63
    .line 64
    :goto_4
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    const-string p0, "viewMode"

    .line 68
    .line 69
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    const-string p0, "unitsType"

    .line 73
    .line 74
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    const-string p0, "endMileage"

    .line 78
    .line 79
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    new-instance v0, Lm70/p0;

    .line 83
    .line 84
    move v2, p2

    .line 85
    invoke-direct/range {v0 .. v8}, Lm70/p0;-><init>(Llf0/i;ZZZLqr0/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
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
    instance-of v1, p1, Lm70/p0;

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
    check-cast p1, Lm70/p0;

    .line 12
    .line 13
    iget-object v1, p0, Lm70/p0;->a:Llf0/i;

    .line 14
    .line 15
    iget-object v3, p1, Lm70/p0;->a:Llf0/i;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lm70/p0;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lm70/p0;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lm70/p0;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lm70/p0;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Lm70/p0;->d:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Lm70/p0;->d:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object v1, p0, Lm70/p0;->e:Lqr0/s;

    .line 42
    .line 43
    iget-object v3, p1, Lm70/p0;->e:Lqr0/s;

    .line 44
    .line 45
    if-eq v1, v3, :cond_6

    .line 46
    .line 47
    return v2

    .line 48
    :cond_6
    iget-object v1, p0, Lm70/p0;->f:Ljava/lang/String;

    .line 49
    .line 50
    iget-object v3, p1, Lm70/p0;->f:Ljava/lang/String;

    .line 51
    .line 52
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-nez v1, :cond_7

    .line 57
    .line 58
    return v2

    .line 59
    :cond_7
    iget-object v1, p0, Lm70/p0;->g:Ljava/lang/String;

    .line 60
    .line 61
    iget-object v3, p1, Lm70/p0;->g:Ljava/lang/String;

    .line 62
    .line 63
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    if-nez v1, :cond_8

    .line 68
    .line 69
    return v2

    .line 70
    :cond_8
    iget-object p0, p0, Lm70/p0;->h:Ljava/lang/String;

    .line 71
    .line 72
    iget-object p1, p1, Lm70/p0;->h:Ljava/lang/String;

    .line 73
    .line 74
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result p0

    .line 78
    if-nez p0, :cond_9

    .line 79
    .line 80
    return v2

    .line 81
    :cond_9
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lm70/p0;->a:Llf0/i;

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
    iget-boolean v2, p0, Lm70/p0;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lm70/p0;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lm70/p0;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lm70/p0;->e:Lqr0/s;

    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    add-int/2addr v2, v0

    .line 35
    mul-int/2addr v2, v1

    .line 36
    iget-object v0, p0, Lm70/p0;->f:Ljava/lang/String;

    .line 37
    .line 38
    invoke-static {v2, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    const/4 v2, 0x0

    .line 43
    iget-object v3, p0, Lm70/p0;->g:Ljava/lang/String;

    .line 44
    .line 45
    if-nez v3, :cond_0

    .line 46
    .line 47
    move v3, v2

    .line 48
    goto :goto_0

    .line 49
    :cond_0
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    :goto_0
    add-int/2addr v0, v3

    .line 54
    mul-int/2addr v0, v1

    .line 55
    iget-object p0, p0, Lm70/p0;->h:Ljava/lang/String;

    .line 56
    .line 57
    if-nez p0, :cond_1

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    :goto_1
    add-int/2addr v0, v2

    .line 65
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(viewMode="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lm70/p0;->a:Llf0/i;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", isLoading="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-boolean v1, p0, Lm70/p0;->b:Z

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", isError="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", noTrips="

    .line 29
    .line 30
    const-string v2, ", unitsType="

    .line 31
    .line 32
    iget-boolean v3, p0, Lm70/p0;->c:Z

    .line 33
    .line 34
    iget-boolean v4, p0, Lm70/p0;->d:Z

    .line 35
    .line 36
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    iget-object v1, p0, Lm70/p0;->e:Lqr0/s;

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v1, ", endMileage="

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    iget-object v1, p0, Lm70/p0;->f:Ljava/lang/String;

    .line 50
    .line 51
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v1, ", averageConsumptionPrimaryText="

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v1, ", averageConsumptionSecondaryText="

    .line 60
    .line 61
    const-string v2, ")"

    .line 62
    .line 63
    iget-object v3, p0, Lm70/p0;->g:Ljava/lang/String;

    .line 64
    .line 65
    iget-object p0, p0, Lm70/p0;->h:Ljava/lang/String;

    .line 66
    .line 67
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0
.end method
