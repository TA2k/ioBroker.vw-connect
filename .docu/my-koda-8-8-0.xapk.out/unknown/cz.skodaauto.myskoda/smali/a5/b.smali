.class public La5/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:La5/h;

.field public b:F

.field public final c:Ljava/util/ArrayList;

.field public final d:La5/a;

.field public e:Z


# direct methods
.method public constructor <init>(Lgw0/c;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-object v0, p0, La5/b;->a:La5/h;

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    iput v0, p0, La5/b;->b:F

    .line 9
    .line 10
    new-instance v0, Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, La5/b;->c:Ljava/util/ArrayList;

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    iput-boolean v0, p0, La5/b;->e:Z

    .line 19
    .line 20
    new-instance v0, La5/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, La5/a;-><init>(La5/b;Lgw0/c;)V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, La5/b;->d:La5/a;

    .line 26
    .line 27
    return-void
.end method


# virtual methods
.method public final a(La5/c;I)V
    .locals 3

    .line 1
    invoke-virtual {p1, p2}, La5/c;->j(I)La5/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/high16 v1, 0x3f800000    # 1.0f

    .line 6
    .line 7
    iget-object v2, p0, La5/b;->d:La5/a;

    .line 8
    .line 9
    invoke-virtual {v2, v0, v1}, La5/a;->g(La5/h;F)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p1, p2}, La5/c;->j(I)La5/h;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    const/high16 p2, -0x40800000    # -1.0f

    .line 17
    .line 18
    iget-object p0, p0, La5/b;->d:La5/a;

    .line 19
    .line 20
    invoke-virtual {p0, p1, p2}, La5/a;->g(La5/h;F)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final b(La5/h;La5/h;La5/h;I)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p4, :cond_1

    .line 3
    .line 4
    if-gez p4, :cond_0

    .line 5
    .line 6
    mul-int/lit8 p4, p4, -0x1

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    :cond_0
    int-to-float p4, p4

    .line 10
    iput p4, p0, La5/b;->b:F

    .line 11
    .line 12
    :cond_1
    const/high16 p4, 0x3f800000    # 1.0f

    .line 13
    .line 14
    const/high16 v1, -0x40800000    # -1.0f

    .line 15
    .line 16
    if-nez v0, :cond_2

    .line 17
    .line 18
    iget-object v0, p0, La5/b;->d:La5/a;

    .line 19
    .line 20
    invoke-virtual {v0, p1, v1}, La5/a;->g(La5/h;F)V

    .line 21
    .line 22
    .line 23
    iget-object p1, p0, La5/b;->d:La5/a;

    .line 24
    .line 25
    invoke-virtual {p1, p2, p4}, La5/a;->g(La5/h;F)V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, La5/b;->d:La5/a;

    .line 29
    .line 30
    invoke-virtual {p0, p3, p4}, La5/a;->g(La5/h;F)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_2
    iget-object v0, p0, La5/b;->d:La5/a;

    .line 35
    .line 36
    invoke-virtual {v0, p1, p4}, La5/a;->g(La5/h;F)V

    .line 37
    .line 38
    .line 39
    iget-object p1, p0, La5/b;->d:La5/a;

    .line 40
    .line 41
    invoke-virtual {p1, p2, v1}, La5/a;->g(La5/h;F)V

    .line 42
    .line 43
    .line 44
    iget-object p0, p0, La5/b;->d:La5/a;

    .line 45
    .line 46
    invoke-virtual {p0, p3, v1}, La5/a;->g(La5/h;F)V

    .line 47
    .line 48
    .line 49
    return-void
.end method

.method public final c(La5/h;La5/h;La5/h;I)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p4, :cond_1

    .line 3
    .line 4
    if-gez p4, :cond_0

    .line 5
    .line 6
    mul-int/lit8 p4, p4, -0x1

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    :cond_0
    int-to-float p4, p4

    .line 10
    iput p4, p0, La5/b;->b:F

    .line 11
    .line 12
    :cond_1
    const/high16 p4, 0x3f800000    # 1.0f

    .line 13
    .line 14
    const/high16 v1, -0x40800000    # -1.0f

    .line 15
    .line 16
    if-nez v0, :cond_2

    .line 17
    .line 18
    iget-object v0, p0, La5/b;->d:La5/a;

    .line 19
    .line 20
    invoke-virtual {v0, p1, v1}, La5/a;->g(La5/h;F)V

    .line 21
    .line 22
    .line 23
    iget-object p1, p0, La5/b;->d:La5/a;

    .line 24
    .line 25
    invoke-virtual {p1, p2, p4}, La5/a;->g(La5/h;F)V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, La5/b;->d:La5/a;

    .line 29
    .line 30
    invoke-virtual {p0, p3, v1}, La5/a;->g(La5/h;F)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_2
    iget-object v0, p0, La5/b;->d:La5/a;

    .line 35
    .line 36
    invoke-virtual {v0, p1, p4}, La5/a;->g(La5/h;F)V

    .line 37
    .line 38
    .line 39
    iget-object p1, p0, La5/b;->d:La5/a;

    .line 40
    .line 41
    invoke-virtual {p1, p2, v1}, La5/a;->g(La5/h;F)V

    .line 42
    .line 43
    .line 44
    iget-object p0, p0, La5/b;->d:La5/a;

    .line 45
    .line 46
    invoke-virtual {p0, p3, p4}, La5/a;->g(La5/h;F)V

    .line 47
    .line 48
    .line 49
    return-void
.end method

.method public d([Z)La5/h;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, v0}, La5/b;->f([ZLa5/h;)La5/h;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    return-object p0
.end method

.method public e()Z
    .locals 2

    .line 1
    iget-object v0, p0, La5/b;->a:La5/h;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget v0, p0, La5/b;->b:F

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    cmpl-float v0, v0, v1

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, La5/b;->d:La5/a;

    .line 13
    .line 14
    invoke-virtual {p0}, La5/a;->d()I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-nez p0, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x1

    .line 21
    return p0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    return p0
.end method

.method public final f([ZLa5/h;)La5/h;
    .locals 9

    .line 1
    iget-object v0, p0, La5/b;->d:La5/a;

    .line 2
    .line 3
    invoke-virtual {v0}, La5/a;->d()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x0

    .line 9
    const/4 v3, 0x0

    .line 10
    move v4, v1

    .line 11
    :goto_0
    if-ge v3, v0, :cond_3

    .line 12
    .line 13
    iget-object v5, p0, La5/b;->d:La5/a;

    .line 14
    .line 15
    invoke-virtual {v5, v3}, La5/a;->f(I)F

    .line 16
    .line 17
    .line 18
    move-result v5

    .line 19
    cmpg-float v6, v5, v1

    .line 20
    .line 21
    if-gez v6, :cond_2

    .line 22
    .line 23
    iget-object v6, p0, La5/b;->d:La5/a;

    .line 24
    .line 25
    invoke-virtual {v6, v3}, La5/a;->e(I)La5/h;

    .line 26
    .line 27
    .line 28
    move-result-object v6

    .line 29
    if-eqz p1, :cond_0

    .line 30
    .line 31
    iget v7, v6, La5/h;->e:I

    .line 32
    .line 33
    aget-boolean v7, p1, v7

    .line 34
    .line 35
    if-nez v7, :cond_2

    .line 36
    .line 37
    :cond_0
    if-eq v6, p2, :cond_2

    .line 38
    .line 39
    iget v7, v6, La5/h;->o:I

    .line 40
    .line 41
    const/4 v8, 0x3

    .line 42
    if-eq v7, v8, :cond_1

    .line 43
    .line 44
    const/4 v8, 0x4

    .line 45
    if-ne v7, v8, :cond_2

    .line 46
    .line 47
    :cond_1
    cmpg-float v7, v5, v4

    .line 48
    .line 49
    if-gez v7, :cond_2

    .line 50
    .line 51
    move v4, v5

    .line 52
    move-object v2, v6

    .line 53
    :cond_2
    add-int/lit8 v3, v3, 0x1

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_3
    return-object v2
.end method

.method public final g(La5/h;)V
    .locals 4

    .line 1
    iget-object v0, p0, La5/b;->a:La5/h;

    .line 2
    .line 3
    const/high16 v1, -0x40800000    # -1.0f

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object v2, p0, La5/b;->d:La5/a;

    .line 8
    .line 9
    invoke-virtual {v2, v0, v1}, La5/a;->g(La5/h;F)V

    .line 10
    .line 11
    .line 12
    iget-object v0, p0, La5/b;->a:La5/h;

    .line 13
    .line 14
    const/4 v2, -0x1

    .line 15
    iput v2, v0, La5/h;->f:I

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    iput-object v0, p0, La5/b;->a:La5/h;

    .line 19
    .line 20
    :cond_0
    iget-object v0, p0, La5/b;->d:La5/a;

    .line 21
    .line 22
    const/4 v2, 0x1

    .line 23
    invoke-virtual {v0, p1, v2}, La5/a;->h(La5/h;Z)F

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    mul-float/2addr v0, v1

    .line 28
    iput-object p1, p0, La5/b;->a:La5/h;

    .line 29
    .line 30
    const/high16 p1, 0x3f800000    # 1.0f

    .line 31
    .line 32
    cmpl-float p1, v0, p1

    .line 33
    .line 34
    if-nez p1, :cond_1

    .line 35
    .line 36
    return-void

    .line 37
    :cond_1
    iget p1, p0, La5/b;->b:F

    .line 38
    .line 39
    div-float/2addr p1, v0

    .line 40
    iput p1, p0, La5/b;->b:F

    .line 41
    .line 42
    iget-object p0, p0, La5/b;->d:La5/a;

    .line 43
    .line 44
    iget p1, p0, La5/a;->h:I

    .line 45
    .line 46
    const/4 v1, 0x0

    .line 47
    :goto_0
    const/4 v2, -0x1

    .line 48
    if-eq p1, v2, :cond_2

    .line 49
    .line 50
    iget v2, p0, La5/a;->a:I

    .line 51
    .line 52
    if-ge v1, v2, :cond_2

    .line 53
    .line 54
    iget-object v2, p0, La5/a;->g:[F

    .line 55
    .line 56
    aget v3, v2, p1

    .line 57
    .line 58
    div-float/2addr v3, v0

    .line 59
    aput v3, v2, p1

    .line 60
    .line 61
    iget-object v2, p0, La5/a;->f:[I

    .line 62
    .line 63
    aget p1, v2, p1

    .line 64
    .line 65
    add-int/lit8 v1, v1, 0x1

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_2
    return-void
.end method

.method public final h(La5/c;La5/h;Z)V
    .locals 3

    .line 1
    iget-boolean v0, p2, La5/h;->i:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    iget-object v0, p0, La5/b;->d:La5/a;

    .line 7
    .line 8
    invoke-virtual {v0, p2}, La5/a;->c(La5/h;)F

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    iget v1, p0, La5/b;->b:F

    .line 13
    .line 14
    iget v2, p2, La5/h;->h:F

    .line 15
    .line 16
    mul-float/2addr v2, v0

    .line 17
    add-float/2addr v2, v1

    .line 18
    iput v2, p0, La5/b;->b:F

    .line 19
    .line 20
    iget-object v0, p0, La5/b;->d:La5/a;

    .line 21
    .line 22
    invoke-virtual {v0, p2, p3}, La5/a;->h(La5/h;Z)F

    .line 23
    .line 24
    .line 25
    if-eqz p3, :cond_1

    .line 26
    .line 27
    invoke-virtual {p2, p0}, La5/h;->b(La5/b;)V

    .line 28
    .line 29
    .line 30
    :cond_1
    iget-object p2, p0, La5/b;->d:La5/a;

    .line 31
    .line 32
    invoke-virtual {p2}, La5/a;->d()I

    .line 33
    .line 34
    .line 35
    move-result p2

    .line 36
    if-nez p2, :cond_2

    .line 37
    .line 38
    const/4 p2, 0x1

    .line 39
    iput-boolean p2, p0, La5/b;->e:Z

    .line 40
    .line 41
    iput-boolean p2, p1, La5/c;->b:Z

    .line 42
    .line 43
    :cond_2
    :goto_0
    return-void
.end method

.method public i(La5/c;La5/b;Z)V
    .locals 7

    .line 1
    iget-object v0, p0, La5/b;->d:La5/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object v1, p2, La5/b;->a:La5/h;

    .line 7
    .line 8
    invoke-virtual {v0, v1}, La5/a;->c(La5/h;)F

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    iget-object v2, p2, La5/b;->a:La5/h;

    .line 13
    .line 14
    invoke-virtual {v0, v2, p3}, La5/a;->h(La5/h;Z)F

    .line 15
    .line 16
    .line 17
    iget-object v2, p2, La5/b;->d:La5/a;

    .line 18
    .line 19
    invoke-virtual {v2}, La5/a;->d()I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    const/4 v4, 0x0

    .line 24
    :goto_0
    if-ge v4, v3, :cond_0

    .line 25
    .line 26
    invoke-virtual {v2, v4}, La5/a;->e(I)La5/h;

    .line 27
    .line 28
    .line 29
    move-result-object v5

    .line 30
    invoke-virtual {v2, v5}, La5/a;->c(La5/h;)F

    .line 31
    .line 32
    .line 33
    move-result v6

    .line 34
    mul-float/2addr v6, v1

    .line 35
    invoke-virtual {v0, v5, v6, p3}, La5/a;->a(La5/h;FZ)V

    .line 36
    .line 37
    .line 38
    add-int/lit8 v4, v4, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    iget v0, p0, La5/b;->b:F

    .line 42
    .line 43
    iget v2, p2, La5/b;->b:F

    .line 44
    .line 45
    mul-float/2addr v2, v1

    .line 46
    add-float/2addr v2, v0

    .line 47
    iput v2, p0, La5/b;->b:F

    .line 48
    .line 49
    if-eqz p3, :cond_1

    .line 50
    .line 51
    iget-object p2, p2, La5/b;->a:La5/h;

    .line 52
    .line 53
    invoke-virtual {p2, p0}, La5/h;->b(La5/b;)V

    .line 54
    .line 55
    .line 56
    :cond_1
    iget-object p2, p0, La5/b;->a:La5/h;

    .line 57
    .line 58
    if-eqz p2, :cond_2

    .line 59
    .line 60
    iget-object p2, p0, La5/b;->d:La5/a;

    .line 61
    .line 62
    invoke-virtual {p2}, La5/a;->d()I

    .line 63
    .line 64
    .line 65
    move-result p2

    .line 66
    if-nez p2, :cond_2

    .line 67
    .line 68
    const/4 p2, 0x1

    .line 69
    iput-boolean p2, p0, La5/b;->e:Z

    .line 70
    .line 71
    iput-boolean p2, p1, La5/c;->b:Z

    .line 72
    .line 73
    :cond_2
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 10

    .line 1
    iget-object v0, p0, La5/b;->a:La5/h;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const-string v0, "0"

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v1, ""

    .line 11
    .line 12
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iget-object v1, p0, La5/b;->a:La5/h;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    :goto_0
    const-string v1, " = "

    .line 25
    .line 26
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    iget v1, p0, La5/b;->b:F

    .line 31
    .line 32
    const/4 v2, 0x0

    .line 33
    cmpl-float v1, v1, v2

    .line 34
    .line 35
    const/4 v3, 0x0

    .line 36
    const/4 v4, 0x1

    .line 37
    if-eqz v1, :cond_1

    .line 38
    .line 39
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    iget v1, p0, La5/b;->b:F

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    move v1, v4

    .line 53
    goto :goto_1

    .line 54
    :cond_1
    move v1, v3

    .line 55
    :goto_1
    iget-object v5, p0, La5/b;->d:La5/a;

    .line 56
    .line 57
    invoke-virtual {v5}, La5/a;->d()I

    .line 58
    .line 59
    .line 60
    move-result v5

    .line 61
    :goto_2
    if-ge v3, v5, :cond_8

    .line 62
    .line 63
    iget-object v6, p0, La5/b;->d:La5/a;

    .line 64
    .line 65
    invoke-virtual {v6, v3}, La5/a;->e(I)La5/h;

    .line 66
    .line 67
    .line 68
    move-result-object v6

    .line 69
    if-nez v6, :cond_2

    .line 70
    .line 71
    goto :goto_6

    .line 72
    :cond_2
    iget-object v7, p0, La5/b;->d:La5/a;

    .line 73
    .line 74
    invoke-virtual {v7, v3}, La5/a;->f(I)F

    .line 75
    .line 76
    .line 77
    move-result v7

    .line 78
    cmpl-float v8, v7, v2

    .line 79
    .line 80
    if-nez v8, :cond_3

    .line 81
    .line 82
    goto :goto_6

    .line 83
    :cond_3
    invoke-virtual {v6}, La5/h;->toString()Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v6

    .line 87
    const/high16 v9, -0x40800000    # -1.0f

    .line 88
    .line 89
    if-nez v1, :cond_4

    .line 90
    .line 91
    cmpg-float v1, v7, v2

    .line 92
    .line 93
    if-gez v1, :cond_6

    .line 94
    .line 95
    const-string v1, "- "

    .line 96
    .line 97
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    :goto_3
    mul-float/2addr v7, v9

    .line 102
    goto :goto_4

    .line 103
    :cond_4
    if-lez v8, :cond_5

    .line 104
    .line 105
    const-string v1, " + "

    .line 106
    .line 107
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    goto :goto_4

    .line 112
    :cond_5
    const-string v1, " - "

    .line 113
    .line 114
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    goto :goto_3

    .line 119
    :cond_6
    :goto_4
    const/high16 v1, 0x3f800000    # 1.0f

    .line 120
    .line 121
    cmpl-float v1, v7, v1

    .line 122
    .line 123
    if-nez v1, :cond_7

    .line 124
    .line 125
    invoke-static {v0, v6}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    goto :goto_5

    .line 130
    :cond_7
    new-instance v1, Ljava/lang/StringBuilder;

    .line 131
    .line 132
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    const-string v0, " "

    .line 142
    .line 143
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 144
    .line 145
    .line 146
    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 147
    .line 148
    .line 149
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    :goto_5
    move v1, v4

    .line 154
    :goto_6
    add-int/lit8 v3, v3, 0x1

    .line 155
    .line 156
    goto :goto_2

    .line 157
    :cond_8
    if-nez v1, :cond_9

    .line 158
    .line 159
    const-string p0, "0.0"

    .line 160
    .line 161
    invoke-static {v0, p0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    return-object p0

    .line 166
    :cond_9
    return-object v0
.end method
