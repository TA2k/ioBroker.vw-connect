.class public final Lin/r1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lin/l0;


# instance fields
.field public final a:Ljava/util/ArrayList;

.field public b:F

.field public c:F

.field public d:Lin/s1;

.field public e:Z

.field public f:Z

.field public g:I

.field public h:Z


# direct methods
.method public constructor <init>(Lin/z1;Li4/c;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance p1, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lin/r1;->a:Ljava/util/ArrayList;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput-object v0, p0, Lin/r1;->d:Lin/s1;

    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    iput-boolean v0, p0, Lin/r1;->e:Z

    .line 16
    .line 17
    const/4 v1, 0x1

    .line 18
    iput-boolean v1, p0, Lin/r1;->f:Z

    .line 19
    .line 20
    const/4 v1, -0x1

    .line 21
    iput v1, p0, Lin/r1;->g:I

    .line 22
    .line 23
    if-nez p2, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    invoke-virtual {p2, p0}, Li4/c;->r(Lin/l0;)V

    .line 27
    .line 28
    .line 29
    iget-boolean p2, p0, Lin/r1;->h:Z

    .line 30
    .line 31
    if-eqz p2, :cond_1

    .line 32
    .line 33
    iget-object p2, p0, Lin/r1;->d:Lin/s1;

    .line 34
    .line 35
    iget v1, p0, Lin/r1;->g:I

    .line 36
    .line 37
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    check-cast v1, Lin/s1;

    .line 42
    .line 43
    invoke-virtual {p2, v1}, Lin/s1;->b(Lin/s1;)V

    .line 44
    .line 45
    .line 46
    iget p2, p0, Lin/r1;->g:I

    .line 47
    .line 48
    iget-object v1, p0, Lin/r1;->d:Lin/s1;

    .line 49
    .line 50
    invoke-virtual {p1, p2, v1}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    iput-boolean v0, p0, Lin/r1;->h:Z

    .line 54
    .line 55
    :cond_1
    iget-object p0, p0, Lin/r1;->d:Lin/s1;

    .line 56
    .line 57
    if-eqz p0, :cond_2

    .line 58
    .line 59
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    :cond_2
    :goto_0
    return-void
.end method


# virtual methods
.method public final a(FFFF)V
    .locals 2

    .line 1
    iget-object v0, p0, Lin/r1;->d:Lin/s1;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Lin/s1;->a(FF)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lin/r1;->a:Ljava/util/ArrayList;

    .line 7
    .line 8
    iget-object v1, p0, Lin/r1;->d:Lin/s1;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    new-instance v0, Lin/s1;

    .line 14
    .line 15
    sub-float p1, p3, p1

    .line 16
    .line 17
    sub-float p2, p4, p2

    .line 18
    .line 19
    invoke-direct {v0, p3, p4, p1, p2}, Lin/s1;-><init>(FFFF)V

    .line 20
    .line 21
    .line 22
    iput-object v0, p0, Lin/r1;->d:Lin/s1;

    .line 23
    .line 24
    const/4 p1, 0x0

    .line 25
    iput-boolean p1, p0, Lin/r1;->h:Z

    .line 26
    .line 27
    return-void
.end method

.method public final b(FF)V
    .locals 3

    .line 1
    iget-boolean v0, p0, Lin/r1;->h:Z

    .line 2
    .line 3
    iget-object v1, p0, Lin/r1;->a:Ljava/util/ArrayList;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lin/r1;->d:Lin/s1;

    .line 8
    .line 9
    iget v2, p0, Lin/r1;->g:I

    .line 10
    .line 11
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    check-cast v2, Lin/s1;

    .line 16
    .line 17
    invoke-virtual {v0, v2}, Lin/s1;->b(Lin/s1;)V

    .line 18
    .line 19
    .line 20
    iget v0, p0, Lin/r1;->g:I

    .line 21
    .line 22
    iget-object v2, p0, Lin/r1;->d:Lin/s1;

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    const/4 v0, 0x0

    .line 28
    iput-boolean v0, p0, Lin/r1;->h:Z

    .line 29
    .line 30
    :cond_0
    iget-object v0, p0, Lin/r1;->d:Lin/s1;

    .line 31
    .line 32
    if-eqz v0, :cond_1

    .line 33
    .line 34
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    :cond_1
    iput p1, p0, Lin/r1;->b:F

    .line 38
    .line 39
    iput p2, p0, Lin/r1;->c:F

    .line 40
    .line 41
    new-instance v0, Lin/s1;

    .line 42
    .line 43
    const/4 v2, 0x0

    .line 44
    invoke-direct {v0, p1, p2, v2, v2}, Lin/s1;-><init>(FFFF)V

    .line 45
    .line 46
    .line 47
    iput-object v0, p0, Lin/r1;->d:Lin/s1;

    .line 48
    .line 49
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 50
    .line 51
    .line 52
    move-result p1

    .line 53
    iput p1, p0, Lin/r1;->g:I

    .line 54
    .line 55
    return-void
.end method

.method public final c(FFFFFF)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lin/r1;->f:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    iget-boolean v0, p0, Lin/r1;->e:Z

    .line 7
    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    :cond_0
    iget-object v0, p0, Lin/r1;->d:Lin/s1;

    .line 11
    .line 12
    invoke-virtual {v0, p1, p2}, Lin/s1;->a(FF)V

    .line 13
    .line 14
    .line 15
    iget-object p1, p0, Lin/r1;->a:Ljava/util/ArrayList;

    .line 16
    .line 17
    iget-object p2, p0, Lin/r1;->d:Lin/s1;

    .line 18
    .line 19
    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    iput-boolean v1, p0, Lin/r1;->e:Z

    .line 23
    .line 24
    :cond_1
    new-instance p1, Lin/s1;

    .line 25
    .line 26
    sub-float p2, p5, p3

    .line 27
    .line 28
    sub-float p3, p6, p4

    .line 29
    .line 30
    invoke-direct {p1, p5, p6, p2, p3}, Lin/s1;-><init>(FFFF)V

    .line 31
    .line 32
    .line 33
    iput-object p1, p0, Lin/r1;->d:Lin/s1;

    .line 34
    .line 35
    iput-boolean v1, p0, Lin/r1;->h:Z

    .line 36
    .line 37
    return-void
.end method

.method public final close()V
    .locals 2

    .line 1
    iget-object v0, p0, Lin/r1;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    iget-object v1, p0, Lin/r1;->d:Lin/s1;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    iget v0, p0, Lin/r1;->b:F

    .line 9
    .line 10
    iget v1, p0, Lin/r1;->c:F

    .line 11
    .line 12
    invoke-virtual {p0, v0, v1}, Lin/r1;->e(FF)V

    .line 13
    .line 14
    .line 15
    const/4 v0, 0x1

    .line 16
    iput-boolean v0, p0, Lin/r1;->h:Z

    .line 17
    .line 18
    return-void
.end method

.method public final d(FFFZZFF)V
    .locals 12

    .line 1
    const/4 v10, 0x1

    .line 2
    iput-boolean v10, p0, Lin/r1;->e:Z

    .line 3
    .line 4
    const/4 v11, 0x0

    .line 5
    iput-boolean v11, p0, Lin/r1;->f:Z

    .line 6
    .line 7
    iget-object v0, p0, Lin/r1;->d:Lin/s1;

    .line 8
    .line 9
    iget v1, v0, Lin/s1;->a:F

    .line 10
    .line 11
    iget v0, v0, Lin/s1;->b:F

    .line 12
    .line 13
    move v2, v1

    .line 14
    move v1, v0

    .line 15
    move v0, v2

    .line 16
    move-object v9, p0

    .line 17
    move v2, p1

    .line 18
    move v3, p2

    .line 19
    move v4, p3

    .line 20
    move/from16 v5, p4

    .line 21
    .line 22
    move/from16 v6, p5

    .line 23
    .line 24
    move/from16 v7, p6

    .line 25
    .line 26
    move/from16 v8, p7

    .line 27
    .line 28
    invoke-static/range {v0 .. v9}, Lin/z1;->h(FFFFFZZFFLin/l0;)V

    .line 29
    .line 30
    .line 31
    iput-boolean v10, p0, Lin/r1;->f:Z

    .line 32
    .line 33
    iput-boolean v11, p0, Lin/r1;->h:Z

    .line 34
    .line 35
    return-void
.end method

.method public final e(FF)V
    .locals 3

    .line 1
    iget-object v0, p0, Lin/r1;->d:Lin/s1;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Lin/s1;->a(FF)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lin/r1;->a:Ljava/util/ArrayList;

    .line 7
    .line 8
    iget-object v1, p0, Lin/r1;->d:Lin/s1;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    new-instance v0, Lin/s1;

    .line 14
    .line 15
    iget-object v1, p0, Lin/r1;->d:Lin/s1;

    .line 16
    .line 17
    iget v2, v1, Lin/s1;->a:F

    .line 18
    .line 19
    sub-float v2, p1, v2

    .line 20
    .line 21
    iget v1, v1, Lin/s1;->b:F

    .line 22
    .line 23
    sub-float v1, p2, v1

    .line 24
    .line 25
    invoke-direct {v0, p1, p2, v2, v1}, Lin/s1;-><init>(FFFF)V

    .line 26
    .line 27
    .line 28
    iput-object v0, p0, Lin/r1;->d:Lin/s1;

    .line 29
    .line 30
    const/4 p1, 0x0

    .line 31
    iput-boolean p1, p0, Lin/r1;->h:Z

    .line 32
    .line 33
    return-void
.end method
