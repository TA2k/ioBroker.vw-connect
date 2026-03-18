.class public final Lvf0/j;
.super Llp/mb;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Lvf0/m;

.field public final d:Ljava/lang/String;

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Z


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;ILjava/lang/String;Z)V
    .locals 11

    and-int/lit8 v0, p2, 0x1

    .line 10
    const-string v1, ""

    if-eqz v0, :cond_0

    move-object v3, v1

    goto :goto_0

    :cond_0
    move-object v3, p1

    :goto_0
    and-int/lit8 p1, p2, 0x2

    if-eqz p1, :cond_1

    move-object v4, v1

    goto :goto_1

    :cond_1
    move-object v4, p3

    .line 11
    :goto_1
    new-instance v5, Lvf0/m;

    .line 12
    sget-object p1, Lvf0/l;->d:Lvf0/l;

    .line 13
    sget-object p3, Lvf0/k;->d:Lvf0/k;

    const/4 v0, 0x0

    .line 14
    invoke-direct {v5, v0, p1, v1, p3}, Lvf0/m;-><init>(Ljava/lang/Integer;Lvf0/l;Ljava/lang/String;Lvf0/k;)V

    and-int/lit8 p1, p2, 0x40

    if-eqz p1, :cond_2

    const/4 p1, 0x1

    :goto_2
    move v9, p1

    goto :goto_3

    :cond_2
    const/4 p1, 0x0

    goto :goto_2

    :goto_3
    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    move-object v2, p0

    move v10, p4

    .line 15
    invoke-direct/range {v2 .. v10}, Lvf0/j;-><init>(Ljava/lang/String;Ljava/lang/String;Lvf0/m;Ljava/lang/String;ZZZZ)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Lvf0/m;Ljava/lang/String;ZZZZ)V
    .locals 1

    const-string v0, "title"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "text"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lvf0/j;->a:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lvf0/j;->b:Ljava/lang/String;

    .line 4
    iput-object p3, p0, Lvf0/j;->c:Lvf0/m;

    .line 5
    iput-object p4, p0, Lvf0/j;->d:Ljava/lang/String;

    .line 6
    iput-boolean p5, p0, Lvf0/j;->e:Z

    .line 7
    iput-boolean p6, p0, Lvf0/j;->f:Z

    .line 8
    iput-boolean p7, p0, Lvf0/j;->g:Z

    .line 9
    iput-boolean p8, p0, Lvf0/j;->h:Z

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
    instance-of v0, p1, Lvf0/j;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Lvf0/j;

    .line 10
    .line 11
    iget-object v0, p0, Lvf0/j;->a:Ljava/lang/String;

    .line 12
    .line 13
    iget-object v1, p1, Lvf0/j;->a:Ljava/lang/String;

    .line 14
    .line 15
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

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
    iget-object v0, p0, Lvf0/j;->b:Ljava/lang/String;

    .line 23
    .line 24
    iget-object v1, p1, Lvf0/j;->b:Ljava/lang/String;

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
    iget-object v0, p0, Lvf0/j;->c:Lvf0/m;

    .line 34
    .line 35
    iget-object v1, p1, Lvf0/j;->c:Lvf0/m;

    .line 36
    .line 37
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

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
    iget-object v0, p0, Lvf0/j;->d:Ljava/lang/String;

    .line 45
    .line 46
    iget-object v1, p1, Lvf0/j;->d:Ljava/lang/String;

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
    iget-boolean v0, p0, Lvf0/j;->e:Z

    .line 56
    .line 57
    iget-boolean v1, p1, Lvf0/j;->e:Z

    .line 58
    .line 59
    if-eq v0, v1, :cond_6

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_6
    iget-boolean v0, p0, Lvf0/j;->f:Z

    .line 63
    .line 64
    iget-boolean v1, p1, Lvf0/j;->f:Z

    .line 65
    .line 66
    if-eq v0, v1, :cond_7

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_7
    iget-boolean v0, p0, Lvf0/j;->g:Z

    .line 70
    .line 71
    iget-boolean v1, p1, Lvf0/j;->g:Z

    .line 72
    .line 73
    if-eq v0, v1, :cond_8

    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_8
    iget-boolean p0, p0, Lvf0/j;->h:Z

    .line 77
    .line 78
    iget-boolean p1, p1, Lvf0/j;->h:Z

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

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lvf0/j;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

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
    iget-object v2, p0, Lvf0/j;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lvf0/j;->c:Lvf0/m;

    .line 17
    .line 18
    invoke-virtual {v2}, Lvf0/m;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v0

    .line 23
    mul-int/2addr v2, v1

    .line 24
    iget-object v0, p0, Lvf0/j;->d:Ljava/lang/String;

    .line 25
    .line 26
    if-nez v0, :cond_0

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    :goto_0
    add-int/2addr v2, v0

    .line 35
    mul-int/2addr v2, v1

    .line 36
    iget-boolean v0, p0, Lvf0/j;->e:Z

    .line 37
    .line 38
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    iget-boolean v2, p0, Lvf0/j;->f:Z

    .line 43
    .line 44
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    iget-boolean v2, p0, Lvf0/j;->g:Z

    .line 49
    .line 50
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    iget-boolean p0, p0, Lvf0/j;->h:Z

    .line 55
    .line 56
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    add-int/2addr p0, v0

    .line 61
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", text="

    .line 2
    .line 3
    const-string v1, ", gaugeData="

    .line 4
    .line 5
    const-string v2, "Single(title="

    .line 6
    .line 7
    iget-object v3, p0, Lvf0/j;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lvf0/j;->b:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-object v1, p0, Lvf0/j;->c:Lvf0/m;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v1, ", warningText="

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lvf0/j;->d:Ljava/lang/String;

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, ", isAdblueLow="

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v1, ", isAdblueCritical="

    .line 36
    .line 37
    const-string v2, ", isEnabled="

    .line 38
    .line 39
    iget-boolean v3, p0, Lvf0/j;->e:Z

    .line 40
    .line 41
    iget-boolean v4, p0, Lvf0/j;->f:Z

    .line 42
    .line 43
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 44
    .line 45
    .line 46
    const-string v1, ", isLoading="

    .line 47
    .line 48
    const-string v2, ")"

    .line 49
    .line 50
    iget-boolean v3, p0, Lvf0/j;->g:Z

    .line 51
    .line 52
    iget-boolean p0, p0, Lvf0/j;->h:Z

    .line 53
    .line 54
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0
.end method
