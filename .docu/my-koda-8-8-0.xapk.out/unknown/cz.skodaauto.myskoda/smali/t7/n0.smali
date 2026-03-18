.class public final Lt7/n0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ljava/lang/Object;

.field public b:Ljava/lang/Object;

.field public c:I

.field public d:J

.field public e:J

.field public f:Z

.field public g:Lt7/b;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    const/4 v0, 0x3

    .line 2
    const/4 v1, 0x4

    .line 3
    const/4 v2, 0x0

    .line 4
    const/4 v3, 0x1

    .line 5
    const/4 v4, 0x2

    .line 6
    invoke-static {v2, v3, v4, v0, v1}, Lp3/m;->w(IIIII)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lt7/b;->c:Lt7/b;

    .line 5
    .line 6
    iput-object v0, p0, Lt7/n0;->g:Lt7/b;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(II)J
    .locals 1

    .line 1
    iget-object p0, p0, Lt7/n0;->g:Lt7/b;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lt7/b;->a(I)Lt7/a;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget p1, p0, Lt7/a;->a:I

    .line 8
    .line 9
    const/4 v0, -0x1

    .line 10
    if-eq p1, v0, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, Lt7/a;->f:[J

    .line 13
    .line 14
    aget-wide p0, p0, p2

    .line 15
    .line 16
    return-wide p0

    .line 17
    :cond_0
    const-wide p0, -0x7fffffffffffffffL    # -4.9E-324

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    return-wide p0
.end method

.method public final b(J)I
    .locals 10

    .line 1
    iget-object v0, p0, Lt7/n0;->g:Lt7/b;

    .line 2
    .line 3
    iget-wide v1, p0, Lt7/n0;->d:J

    .line 4
    .line 5
    iget p0, v0, Lt7/b;->a:I

    .line 6
    .line 7
    const-wide/high16 v3, -0x8000000000000000L

    .line 8
    .line 9
    cmp-long v3, p1, v3

    .line 10
    .line 11
    const/4 v4, -0x1

    .line 12
    if-eqz v3, :cond_4

    .line 13
    .line 14
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 15
    .line 16
    .line 17
    .line 18
    .line 19
    cmp-long v3, v1, v5

    .line 20
    .line 21
    if-eqz v3, :cond_0

    .line 22
    .line 23
    cmp-long v5, p1, v1

    .line 24
    .line 25
    if-ltz v5, :cond_0

    .line 26
    .line 27
    goto :goto_2

    .line 28
    :cond_0
    const/4 v5, 0x0

    .line 29
    :goto_0
    const-wide/16 v6, 0x0

    .line 30
    .line 31
    if-ge v5, p0, :cond_2

    .line 32
    .line 33
    invoke-virtual {v0, v5}, Lt7/b;->a(I)Lt7/a;

    .line 34
    .line 35
    .line 36
    move-result-object v8

    .line 37
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0, v5}, Lt7/b;->a(I)Lt7/a;

    .line 41
    .line 42
    .line 43
    move-result-object v8

    .line 44
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    cmp-long v8, v6, p1

    .line 48
    .line 49
    if-lez v8, :cond_1

    .line 50
    .line 51
    invoke-virtual {v0, v5}, Lt7/b;->a(I)Lt7/a;

    .line 52
    .line 53
    .line 54
    move-result-object v8

    .line 55
    iget v9, v8, Lt7/a;->a:I

    .line 56
    .line 57
    if-eq v9, v4, :cond_2

    .line 58
    .line 59
    invoke-virtual {v8, v4}, Lt7/a;->a(I)I

    .line 60
    .line 61
    .line 62
    move-result v8

    .line 63
    if-ge v8, v9, :cond_1

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_1
    add-int/lit8 v5, v5, 0x1

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_2
    :goto_1
    if-ge v5, p0, :cond_4

    .line 70
    .line 71
    if-eqz v3, :cond_3

    .line 72
    .line 73
    invoke-virtual {v0, v5}, Lt7/b;->a(I)Lt7/a;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 78
    .line 79
    .line 80
    cmp-long p0, v6, v1

    .line 81
    .line 82
    if-gtz p0, :cond_4

    .line 83
    .line 84
    :cond_3
    return v5

    .line 85
    :cond_4
    :goto_2
    return v4
.end method

.method public final c(J)I
    .locals 5

    .line 1
    iget-object p0, p0, Lt7/n0;->g:Lt7/b;

    .line 2
    .line 3
    iget v0, p0, Lt7/b;->a:I

    .line 4
    .line 5
    add-int/lit8 v1, v0, -0x1

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    sub-int/2addr v0, v2

    .line 9
    if-ne v1, v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0, v1}, Lt7/b;->a(I)Lt7/a;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    :cond_0
    :goto_0
    if-ltz v1, :cond_2

    .line 19
    .line 20
    const-wide/high16 v3, -0x8000000000000000L

    .line 21
    .line 22
    cmp-long v0, p1, v3

    .line 23
    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    invoke-virtual {p0, v1}, Lt7/b;->a(I)Lt7/a;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    const-wide/16 v3, 0x0

    .line 35
    .line 36
    cmp-long v0, p1, v3

    .line 37
    .line 38
    if-gez v0, :cond_2

    .line 39
    .line 40
    add-int/lit8 v1, v1, -0x1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_2
    :goto_1
    const/4 p1, -0x1

    .line 44
    if-ltz v1, :cond_6

    .line 45
    .line 46
    invoke-virtual {p0, v1}, Lt7/b;->a(I)Lt7/a;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    iget p2, p0, Lt7/a;->a:I

    .line 51
    .line 52
    if-ne p2, p1, :cond_3

    .line 53
    .line 54
    goto :goto_3

    .line 55
    :cond_3
    const/4 v0, 0x0

    .line 56
    :goto_2
    if-ge v0, p2, :cond_6

    .line 57
    .line 58
    iget-object v3, p0, Lt7/a;->e:[I

    .line 59
    .line 60
    aget v3, v3, v0

    .line 61
    .line 62
    if-eqz v3, :cond_5

    .line 63
    .line 64
    if-ne v3, v2, :cond_4

    .line 65
    .line 66
    goto :goto_3

    .line 67
    :cond_4
    add-int/lit8 v0, v0, 0x1

    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_5
    :goto_3
    return v1

    .line 71
    :cond_6
    return p1
.end method

.method public final d(I)J
    .locals 0

    .line 1
    iget-object p0, p0, Lt7/n0;->g:Lt7/b;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lt7/b;->a(I)Lt7/a;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const-wide/16 p0, 0x0

    .line 11
    .line 12
    return-wide p0
.end method

.method public final e(I)I
    .locals 0

    .line 1
    iget-object p0, p0, Lt7/n0;->g:Lt7/b;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lt7/b;->a(I)Lt7/a;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const/4 p1, -0x1

    .line 8
    invoke-virtual {p0, p1}, Lt7/a;->a(I)I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    if-eqz p1, :cond_2

    .line 5
    .line 6
    const-class v0, Lt7/n0;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_1
    check-cast p1, Lt7/n0;

    .line 20
    .line 21
    iget-object v0, p0, Lt7/n0;->a:Ljava/lang/Object;

    .line 22
    .line 23
    iget-object v1, p1, Lt7/n0;->a:Ljava/lang/Object;

    .line 24
    .line 25
    invoke-static {v0, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_2

    .line 30
    .line 31
    iget-object v0, p0, Lt7/n0;->b:Ljava/lang/Object;

    .line 32
    .line 33
    iget-object v1, p1, Lt7/n0;->b:Ljava/lang/Object;

    .line 34
    .line 35
    invoke-static {v0, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-eqz v0, :cond_2

    .line 40
    .line 41
    iget v0, p0, Lt7/n0;->c:I

    .line 42
    .line 43
    iget v1, p1, Lt7/n0;->c:I

    .line 44
    .line 45
    if-ne v0, v1, :cond_2

    .line 46
    .line 47
    iget-wide v0, p0, Lt7/n0;->d:J

    .line 48
    .line 49
    iget-wide v2, p1, Lt7/n0;->d:J

    .line 50
    .line 51
    cmp-long v0, v0, v2

    .line 52
    .line 53
    if-nez v0, :cond_2

    .line 54
    .line 55
    iget-wide v0, p0, Lt7/n0;->e:J

    .line 56
    .line 57
    iget-wide v2, p1, Lt7/n0;->e:J

    .line 58
    .line 59
    cmp-long v0, v0, v2

    .line 60
    .line 61
    if-nez v0, :cond_2

    .line 62
    .line 63
    iget-boolean v0, p0, Lt7/n0;->f:Z

    .line 64
    .line 65
    iget-boolean v1, p1, Lt7/n0;->f:Z

    .line 66
    .line 67
    if-ne v0, v1, :cond_2

    .line 68
    .line 69
    iget-object p0, p0, Lt7/n0;->g:Lt7/b;

    .line 70
    .line 71
    iget-object p1, p1, Lt7/n0;->g:Lt7/b;

    .line 72
    .line 73
    invoke-static {p0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    if-eqz p0, :cond_2

    .line 78
    .line 79
    :goto_0
    const/4 p0, 0x1

    .line 80
    return p0

    .line 81
    :cond_2
    :goto_1
    const/4 p0, 0x0

    .line 82
    return p0
.end method

.method public final f(I)Z
    .locals 2

    .line 1
    iget-object p0, p0, Lt7/n0;->g:Lt7/b;

    .line 2
    .line 3
    iget v0, p0, Lt7/b;->a:I

    .line 4
    .line 5
    add-int/lit8 v1, v0, -0x1

    .line 6
    .line 7
    if-ne p1, v1, :cond_0

    .line 8
    .line 9
    add-int/lit8 v0, v0, -0x1

    .line 10
    .line 11
    if-ne p1, v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lt7/b;->a(I)Lt7/a;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    :cond_0
    const/4 p0, 0x0

    .line 21
    return p0
.end method

.method public final g(I)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lt7/n0;->g:Lt7/b;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lt7/b;->a(I)Lt7/a;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    return p0
.end method

.method public final h(Ljava/lang/Object;Ljava/lang/Object;IJJLt7/b;Z)V
    .locals 0

    .line 1
    iput-object p1, p0, Lt7/n0;->a:Ljava/lang/Object;

    .line 2
    .line 3
    iput-object p2, p0, Lt7/n0;->b:Ljava/lang/Object;

    .line 4
    .line 5
    iput p3, p0, Lt7/n0;->c:I

    .line 6
    .line 7
    iput-wide p4, p0, Lt7/n0;->d:J

    .line 8
    .line 9
    iput-wide p6, p0, Lt7/n0;->e:J

    .line 10
    .line 11
    iput-object p8, p0, Lt7/n0;->g:Lt7/b;

    .line 12
    .line 13
    iput-boolean p9, p0, Lt7/n0;->f:Z

    .line 14
    .line 15
    return-void
.end method

.method public final hashCode()I
    .locals 6

    .line 1
    iget-object v0, p0, Lt7/n0;->a:Ljava/lang/Object;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    move v0, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    :goto_0
    const/16 v2, 0xd9

    .line 13
    .line 14
    add-int/2addr v2, v0

    .line 15
    mul-int/lit8 v2, v2, 0x1f

    .line 16
    .line 17
    iget-object v0, p0, Lt7/n0;->b:Ljava/lang/Object;

    .line 18
    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_1
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    :goto_1
    add-int/2addr v2, v1

    .line 27
    mul-int/lit8 v2, v2, 0x1f

    .line 28
    .line 29
    iget v0, p0, Lt7/n0;->c:I

    .line 30
    .line 31
    add-int/2addr v2, v0

    .line 32
    mul-int/lit8 v2, v2, 0x1f

    .line 33
    .line 34
    iget-wide v0, p0, Lt7/n0;->d:J

    .line 35
    .line 36
    const/16 v3, 0x20

    .line 37
    .line 38
    ushr-long v4, v0, v3

    .line 39
    .line 40
    xor-long/2addr v0, v4

    .line 41
    long-to-int v0, v0

    .line 42
    add-int/2addr v2, v0

    .line 43
    mul-int/lit8 v2, v2, 0x1f

    .line 44
    .line 45
    iget-wide v0, p0, Lt7/n0;->e:J

    .line 46
    .line 47
    ushr-long v3, v0, v3

    .line 48
    .line 49
    xor-long/2addr v0, v3

    .line 50
    long-to-int v0, v0

    .line 51
    add-int/2addr v2, v0

    .line 52
    mul-int/lit8 v2, v2, 0x1f

    .line 53
    .line 54
    iget-boolean v0, p0, Lt7/n0;->f:Z

    .line 55
    .line 56
    add-int/2addr v2, v0

    .line 57
    mul-int/lit8 v2, v2, 0x1f

    .line 58
    .line 59
    iget-object p0, p0, Lt7/n0;->g:Lt7/b;

    .line 60
    .line 61
    invoke-virtual {p0}, Lt7/b;->hashCode()I

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    add-int/2addr p0, v2

    .line 66
    return p0
.end method
