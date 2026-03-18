.class public final Lv71/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final i:Lv71/b;


# instance fields
.field public final a:Lw71/c;

.field public final b:Lw71/c;

.field public final c:Lv71/c;

.field public final d:Lv71/a;

.field public final e:Ls71/o;

.field public final f:D

.field public final g:Lv71/d;

.field public final h:Z


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    new-instance v0, Lv71/b;

    .line 2
    .line 3
    new-instance v1, Lw71/c;

    .line 4
    .line 5
    const-wide/16 v2, 0x0

    .line 6
    .line 7
    invoke-direct {v1, v2, v3, v2, v3}, Lw71/c;-><init>(DD)V

    .line 8
    .line 9
    .line 10
    move-wide v3, v2

    .line 11
    new-instance v2, Lw71/c;

    .line 12
    .line 13
    invoke-direct {v2, v3, v4, v3, v4}, Lw71/c;-><init>(DD)V

    .line 14
    .line 15
    .line 16
    new-instance v3, Lv71/c;

    .line 17
    .line 18
    sget-object v4, Lmx0/s;->d:Lmx0/s;

    .line 19
    .line 20
    invoke-direct {v3, v4}, Lv71/c;-><init>(Ljava/util/List;)V

    .line 21
    .line 22
    .line 23
    sget-object v5, Ls71/o;->d:Ls71/o;

    .line 24
    .line 25
    new-instance v8, Lv71/d;

    .line 26
    .line 27
    invoke-direct {v8, v4, v4}, Lv71/d;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 28
    .line 29
    .line 30
    const/4 v9, 0x1

    .line 31
    const/4 v4, 0x0

    .line 32
    const-wide/16 v6, 0x0

    .line 33
    .line 34
    invoke-direct/range {v0 .. v9}, Lv71/b;-><init>(Lw71/c;Lw71/c;Lv71/c;Lv71/a;Ls71/o;DLv71/d;Z)V

    .line 35
    .line 36
    .line 37
    sput-object v0, Lv71/b;->i:Lv71/b;

    .line 38
    .line 39
    return-void
.end method

.method public constructor <init>(Lw71/c;Lw71/c;Lv71/c;Lv71/a;Ls71/o;DLv71/d;Z)V
    .locals 1

    .line 1
    const-string v0, "centerVehiclePosition"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "direction"

    .line 7
    .line 8
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lv71/b;->a:Lw71/c;

    .line 15
    .line 16
    iput-object p2, p0, Lv71/b;->b:Lw71/c;

    .line 17
    .line 18
    iput-object p3, p0, Lv71/b;->c:Lv71/c;

    .line 19
    .line 20
    iput-object p4, p0, Lv71/b;->d:Lv71/a;

    .line 21
    .line 22
    iput-object p5, p0, Lv71/b;->e:Ls71/o;

    .line 23
    .line 24
    iput-wide p6, p0, Lv71/b;->f:D

    .line 25
    .line 26
    iput-object p8, p0, Lv71/b;->g:Lv71/d;

    .line 27
    .line 28
    iput-boolean p9, p0, Lv71/b;->h:Z

    .line 29
    .line 30
    return-void
.end method

.method public static a(Lv71/b;Z)Lv71/b;
    .locals 10

    .line 1
    iget-object v1, p0, Lv71/b;->a:Lw71/c;

    .line 2
    .line 3
    iget-object v2, p0, Lv71/b;->b:Lw71/c;

    .line 4
    .line 5
    iget-object v3, p0, Lv71/b;->c:Lv71/c;

    .line 6
    .line 7
    iget-object v4, p0, Lv71/b;->d:Lv71/a;

    .line 8
    .line 9
    iget-object v5, p0, Lv71/b;->e:Ls71/o;

    .line 10
    .line 11
    iget-wide v6, p0, Lv71/b;->f:D

    .line 12
    .line 13
    iget-object v8, p0, Lv71/b;->g:Lv71/d;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    const-string p0, "centerVehiclePosition"

    .line 19
    .line 20
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const-string p0, "direction"

    .line 24
    .line 25
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    new-instance v0, Lv71/b;

    .line 29
    .line 30
    move v9, p1

    .line 31
    invoke-direct/range {v0 .. v9}, Lv71/b;-><init>(Lw71/c;Lw71/c;Lv71/c;Lv71/a;Ls71/o;DLv71/d;Z)V

    .line 32
    .line 33
    .line 34
    return-object v0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of v0, p1, Lv71/b;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Lv71/b;

    .line 10
    .line 11
    iget-object v0, p0, Lv71/b;->a:Lw71/c;

    .line 12
    .line 13
    iget-object v1, p1, Lv71/b;->a:Lw71/c;

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Lw71/c;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez v0, :cond_2

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_2
    iget-object v0, p0, Lv71/b;->b:Lw71/c;

    .line 23
    .line 24
    iget-object v1, p1, Lv71/b;->b:Lw71/c;

    .line 25
    .line 26
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-nez v0, :cond_3

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_3
    iget-object v0, p0, Lv71/b;->c:Lv71/c;

    .line 34
    .line 35
    iget-object v1, p1, Lv71/b;->c:Lv71/c;

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Lv71/c;->equals(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-nez v0, :cond_4

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_4
    iget-object v0, p0, Lv71/b;->d:Lv71/a;

    .line 45
    .line 46
    iget-object v1, p1, Lv71/b;->d:Lv71/a;

    .line 47
    .line 48
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    if-nez v0, :cond_5

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_5
    iget-object v0, p0, Lv71/b;->e:Ls71/o;

    .line 56
    .line 57
    iget-object v1, p1, Lv71/b;->e:Ls71/o;

    .line 58
    .line 59
    if-eq v0, v1, :cond_6

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_6
    iget-wide v0, p0, Lv71/b;->f:D

    .line 63
    .line 64
    iget-wide v2, p1, Lv71/b;->f:D

    .line 65
    .line 66
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Double;->compare(DD)I

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    if-eqz v0, :cond_7

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_7
    iget-object v0, p0, Lv71/b;->g:Lv71/d;

    .line 74
    .line 75
    iget-object v1, p1, Lv71/b;->g:Lv71/d;

    .line 76
    .line 77
    invoke-virtual {v0, v1}, Lv71/d;->equals(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    if-nez v0, :cond_8

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_8
    iget-boolean p0, p0, Lv71/b;->h:Z

    .line 85
    .line 86
    iget-boolean p1, p1, Lv71/b;->h:Z

    .line 87
    .line 88
    if-eq p0, p1, :cond_9

    .line 89
    .line 90
    :goto_0
    const/4 p0, 0x0

    .line 91
    return p0

    .line 92
    :cond_9
    :goto_1
    const/4 p0, 0x1

    .line 93
    return p0
.end method

.method public final hashCode()I
    .locals 5

    .line 1
    iget-object v0, p0, Lv71/b;->a:Lw71/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Lw71/c;->hashCode()I

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
    iget-object v2, p0, Lv71/b;->b:Lw71/c;

    .line 11
    .line 12
    invoke-virtual {v2}, Lw71/c;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    iget-object v0, p0, Lv71/b;->c:Lv71/c;

    .line 19
    .line 20
    iget-object v0, v0, Lv71/c;->a:Ljava/lang/Object;

    .line 21
    .line 22
    invoke-static {v2, v0, v1}, Lp3/m;->b(ILjava/lang/Object;I)I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    iget-object v2, p0, Lv71/b;->d:Lv71/a;

    .line 27
    .line 28
    if-nez v2, :cond_0

    .line 29
    .line 30
    const/4 v2, 0x0

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {v2}, Lv71/a;->hashCode()I

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    :goto_0
    add-int/2addr v0, v2

    .line 37
    mul-int/2addr v0, v1

    .line 38
    iget-object v2, p0, Lv71/b;->e:Ls71/o;

    .line 39
    .line 40
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    add-int/2addr v2, v0

    .line 45
    mul-int/2addr v2, v1

    .line 46
    iget-wide v3, p0, Lv71/b;->f:D

    .line 47
    .line 48
    invoke-static {v3, v4, v2, v1}, Lf2/m0;->a(DII)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-object v2, p0, Lv71/b;->g:Lv71/d;

    .line 53
    .line 54
    invoke-virtual {v2}, Lv71/d;->hashCode()I

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    add-int/2addr v2, v0

    .line 59
    mul-int/2addr v2, v1

    .line 60
    iget-boolean p0, p0, Lv71/b;->h:Z

    .line 61
    .line 62
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    add-int/2addr p0, v2

    .line 67
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "TrajectoryData(rearAxisVehiclePosition="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lv71/b;->a:Lw71/c;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", centerVehiclePosition="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lv71/b;->b:Lw71/c;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", mesh="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lv71/b;->c:Lv71/c;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", lastMove="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lv71/b;->d:Lv71/a;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", direction="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lv71/b;->e:Ls71/o;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", vehicleAngleInRad="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-wide v1, p0, Lv71/b;->f:D

    .line 59
    .line 60
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", trajectoryBorder="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lv71/b;->g:Lv71/d;

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", shouldShowBackgroundGrid="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-boolean p0, p0, Lv71/b;->h:Z

    .line 79
    .line 80
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string p0, ")"

    .line 84
    .line 85
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    return-object p0
.end method
