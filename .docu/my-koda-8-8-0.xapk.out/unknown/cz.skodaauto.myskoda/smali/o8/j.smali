.class public abstract Lo8/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public b:I

.field public final c:Ljava/lang/Object;

.field public d:Ljava/lang/Object;

.field public e:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 5

    const/4 v0, 0x1

    iput v0, p0, Lo8/j;->a:I

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    new-instance v0, Lbb/g0;

    const/16 v1, 0x13

    const/4 v2, 0x0

    .line 7
    invoke-direct {v0, v2, v1}, Lbb/g0;-><init>(CI)V

    const/16 v1, 0x8

    .line 8
    new-array v2, v1, [Ljava/lang/Object;

    iput-object v2, v0, Lbb/g0;->f:Ljava/lang/Object;

    .line 9
    new-array v2, v1, [I

    const/4 v3, 0x0

    :goto_0
    const/4 v4, -0x1

    if-ge v3, v1, :cond_0

    aput v4, v2, v3

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    iput-object v2, v0, Lbb/g0;->g:Ljava/lang/Object;

    .line 10
    iput v4, v0, Lbb/g0;->e:I

    .line 11
    iput-object v0, p0, Lo8/j;->c:Ljava/lang/Object;

    .line 12
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iput-object v0, p0, Lo8/j;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lo8/g;Lo8/i;JJJJJI)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lo8/j;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p2, p0, Lo8/j;->d:Ljava/lang/Object;

    .line 3
    iput p13, p0, Lo8/j;->b:I

    move-object p2, p1

    .line 4
    new-instance p1, Lo8/e;

    invoke-direct/range {p1 .. p12}, Lo8/e;-><init>(Lo8/g;JJJJJ)V

    iput-object p1, p0, Lo8/j;->c:Ljava/lang/Object;

    return-void
.end method

.method public static A(Lo8/p;JLo8/s;)I
    .locals 2

    .line 1
    invoke-interface {p0}, Lo8/p;->getPosition()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    cmp-long p0, p1, v0

    .line 6
    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_0
    iput-wide p1, p3, Lo8/s;->a:J

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0
.end method

.method public static synthetic r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V
    .locals 1

    .line 1
    and-int/lit8 v0, p4, 0x2

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget p2, p0, Lo8/j;->b:I

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p4, p4, 0x4

    .line 8
    .line 9
    if-eqz p4, :cond_1

    .line 10
    .line 11
    const-string p3, ""

    .line 12
    .line 13
    :cond_1
    invoke-virtual {p0, p1, p2, p3}, Lo8/j;->q(Ljava/lang/String;ILjava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    throw p0
.end method

.method public static v(C)Z
    .locals 1

    .line 1
    const/16 v0, 0x2c

    .line 2
    .line 3
    if-eq p0, v0, :cond_0

    .line 4
    .line 5
    const/16 v0, 0x3a

    .line 6
    .line 7
    if-eq p0, v0, :cond_0

    .line 8
    .line 9
    const/16 v0, 0x5d

    .line 10
    .line 11
    if-eq p0, v0, :cond_0

    .line 12
    .line 13
    const/16 v0, 0x7d

    .line 14
    .line 15
    if-eq p0, v0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method


# virtual methods
.method public B(J)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-wide/from16 v2, p1

    .line 4
    .line 5
    iget-object v1, v0, Lo8/j;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lo8/f;

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    iget-wide v4, v1, Lo8/f;->a:J

    .line 12
    .line 13
    cmp-long v1, v4, v2

    .line 14
    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    new-instance v1, Lo8/f;

    .line 19
    .line 20
    iget-object v4, v0, Lo8/j;->c:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v4, Lo8/e;

    .line 23
    .line 24
    iget-object v5, v4, Lo8/e;->a:Lo8/g;

    .line 25
    .line 26
    invoke-interface {v5, v2, v3}, Lo8/g;->a(J)J

    .line 27
    .line 28
    .line 29
    move-result-wide v5

    .line 30
    move-wide v8, v5

    .line 31
    iget-wide v6, v4, Lo8/e;->c:J

    .line 32
    .line 33
    move-wide v10, v8

    .line 34
    iget-wide v8, v4, Lo8/e;->d:J

    .line 35
    .line 36
    move-wide v12, v10

    .line 37
    iget-wide v10, v4, Lo8/e;->e:J

    .line 38
    .line 39
    iget-wide v4, v4, Lo8/e;->f:J

    .line 40
    .line 41
    move-wide v14, v12

    .line 42
    move-wide v12, v4

    .line 43
    move-wide v4, v14

    .line 44
    invoke-direct/range {v1 .. v13}, Lo8/f;-><init>(JJJJJJ)V

    .line 45
    .line 46
    .line 47
    iput-object v1, v0, Lo8/j;->e:Ljava/lang/Object;

    .line 48
    .line 49
    return-void
.end method

.method public abstract C()I
.end method

.method public D(II)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0, p1, p2}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public E()Z
    .locals 3

    .line 1
    invoke-virtual {p0}, Lo8/j;->C()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    if-ge v0, v2, :cond_1

    .line 14
    .line 15
    const/4 v2, -0x1

    .line 16
    if-ne v0, v2, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    invoke-interface {v1, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    const/16 v1, 0x2c

    .line 24
    .line 25
    if-ne v0, v1, :cond_1

    .line 26
    .line 27
    iget v0, p0, Lo8/j;->b:I

    .line 28
    .line 29
    const/4 v1, 0x1

    .line 30
    add-int/2addr v0, v1

    .line 31
    iput v0, p0, Lo8/j;->b:I

    .line 32
    .line 33
    return v1

    .line 34
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 35
    return p0
.end method

.method public F(C)V
    .locals 6

    .line 1
    iget v0, p0, Lo8/j;->b:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-lez v0, :cond_1

    .line 5
    .line 6
    const/16 v2, 0x22

    .line 7
    .line 8
    if-ne p1, v2, :cond_1

    .line 9
    .line 10
    add-int/lit8 v2, v0, -0x1

    .line 11
    .line 12
    :try_start_0
    iput v2, p0, Lo8/j;->b:I

    .line 13
    .line 14
    invoke-virtual {p0}, Lo8/j;->l()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    iput v0, p0, Lo8/j;->b:I

    .line 19
    .line 20
    const-string v0, "null"

    .line 21
    .line 22
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-nez v0, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    iget p1, p0, Lo8/j;->b:I

    .line 30
    .line 31
    add-int/lit8 p1, p1, -0x1

    .line 32
    .line 33
    const-string v0, "Use \'coerceInputValues = true\' in \'Json {}\' builder to coerce nulls if property has a default value."

    .line 34
    .line 35
    const-string v2, "Expected string literal but \'null\' literal was found"

    .line 36
    .line 37
    invoke-virtual {p0, v2, p1, v0}, Lo8/j;->q(Ljava/lang/String;ILjava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw v1

    .line 41
    :catchall_0
    move-exception p1

    .line 42
    iput v0, p0, Lo8/j;->b:I

    .line 43
    .line 44
    throw p1

    .line 45
    :cond_1
    :goto_0
    invoke-static {p1}, Lwz0/p;->g(C)B

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    invoke-static {p1}, Lwz0/p;->s(B)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    iget v0, p0, Lo8/j;->b:I

    .line 54
    .line 55
    add-int/lit8 v2, v0, -0x1

    .line 56
    .line 57
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 58
    .line 59
    .line 60
    move-result-object v3

    .line 61
    invoke-interface {v3}, Ljava/lang/CharSequence;->length()I

    .line 62
    .line 63
    .line 64
    move-result v3

    .line 65
    if-eq v0, v3, :cond_3

    .line 66
    .line 67
    if-gez v2, :cond_2

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_2
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    invoke-interface {v0, v2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    invoke-static {v0}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    goto :goto_2

    .line 83
    :cond_3
    :goto_1
    const-string v0, "EOF"

    .line 84
    .line 85
    :goto_2
    const-string v3, ", but had \'"

    .line 86
    .line 87
    const-string v4, "\' instead"

    .line 88
    .line 89
    const-string v5, "Expected "

    .line 90
    .line 91
    invoke-static {v5, p1, v3, v0, v4}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    const/4 v0, 0x4

    .line 96
    invoke-static {p0, p1, v2, v1, v0}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 97
    .line 98
    .line 99
    throw v1
.end method

.method public a(ILjava/lang/CharSequence;)I
    .locals 4

    .line 1
    add-int/lit8 v0, p1, 0x4

    .line 2
    .line 3
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-lt v0, v1, :cond_1

    .line 8
    .line 9
    iput p1, p0, Lo8/j;->b:I

    .line 10
    .line 11
    invoke-virtual {p0}, Lo8/j;->o()V

    .line 12
    .line 13
    .line 14
    iget p1, p0, Lo8/j;->b:I

    .line 15
    .line 16
    add-int/lit8 p1, p1, 0x4

    .line 17
    .line 18
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-ge p1, v0, :cond_0

    .line 23
    .line 24
    iget p1, p0, Lo8/j;->b:I

    .line 25
    .line 26
    invoke-virtual {p0, p1, p2}, Lo8/j;->a(ILjava/lang/CharSequence;)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    return p0

    .line 31
    :cond_0
    const/4 p1, 0x0

    .line 32
    const/4 p2, 0x6

    .line 33
    const-string v0, "Unexpected EOF during unicode escape"

    .line 34
    .line 35
    const/4 v1, 0x0

    .line 36
    invoke-static {p0, v0, p1, v1, p2}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    throw v1

    .line 40
    :cond_1
    iget-object v1, p0, Lo8/j;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v1, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Lo8/j;->s(ILjava/lang/CharSequence;)I

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    shl-int/lit8 v2, v2, 0xc

    .line 49
    .line 50
    add-int/lit8 v3, p1, 0x1

    .line 51
    .line 52
    invoke-virtual {p0, v3, p2}, Lo8/j;->s(ILjava/lang/CharSequence;)I

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    shl-int/lit8 v3, v3, 0x8

    .line 57
    .line 58
    add-int/2addr v2, v3

    .line 59
    add-int/lit8 v3, p1, 0x2

    .line 60
    .line 61
    invoke-virtual {p0, v3, p2}, Lo8/j;->s(ILjava/lang/CharSequence;)I

    .line 62
    .line 63
    .line 64
    move-result v3

    .line 65
    shl-int/lit8 v3, v3, 0x4

    .line 66
    .line 67
    add-int/2addr v2, v3

    .line 68
    add-int/lit8 p1, p1, 0x3

    .line 69
    .line 70
    invoke-virtual {p0, p1, p2}, Lo8/j;->s(ILjava/lang/CharSequence;)I

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    add-int/2addr p0, v2

    .line 75
    int-to-char p0, p0

    .line 76
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    return v0
.end method

.method public b(II)V
    .locals 1

    .line 1
    iget-object v0, p0, Lo8/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {v0, p0, p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public abstract c()Z
.end method

.method public d(ILjava/lang/String;)V
    .locals 8

    .line 1
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Ljava/lang/CharSequence;->length()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    sub-int/2addr v0, p1

    .line 10
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    const/4 v2, 0x6

    .line 15
    const/4 v3, 0x0

    .line 16
    const/4 v4, 0x0

    .line 17
    if-lt v0, v1, :cond_2

    .line 18
    .line 19
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    move v1, v3

    .line 24
    :goto_0
    if-ge v1, v0, :cond_1

    .line 25
    .line 26
    invoke-virtual {p2, v1}, Ljava/lang/String;->charAt(I)C

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 31
    .line 32
    .line 33
    move-result-object v6

    .line 34
    add-int v7, p1, v1

    .line 35
    .line 36
    invoke-interface {v6, v7}, Ljava/lang/CharSequence;->charAt(I)C

    .line 37
    .line 38
    .line 39
    move-result v6

    .line 40
    or-int/lit8 v6, v6, 0x20

    .line 41
    .line 42
    if-ne v5, v6, :cond_0

    .line 43
    .line 44
    add-int/lit8 v1, v1, 0x1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    new-instance p1, Ljava/lang/StringBuilder;

    .line 48
    .line 49
    const-string p2, "Expected valid boolean literal prefix, but had \'"

    .line 50
    .line 51
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {p0}, Lo8/j;->l()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p2

    .line 58
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const/16 p2, 0x27

    .line 62
    .line 63
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    invoke-static {p0, p1, v3, v4, v2}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 71
    .line 72
    .line 73
    throw v4

    .line 74
    :cond_1
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 75
    .line 76
    .line 77
    move-result p2

    .line 78
    add-int/2addr p2, p1

    .line 79
    iput p2, p0, Lo8/j;->b:I

    .line 80
    .line 81
    return-void

    .line 82
    :cond_2
    const-string p1, "Unexpected end of boolean literal"

    .line 83
    .line 84
    invoke-static {p0, p1, v3, v4, v2}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 85
    .line 86
    .line 87
    throw v4
.end method

.method public abstract e()Ljava/lang/String;
.end method

.method public abstract f()B
.end method

.method public g(B)B
    .locals 5

    .line 1
    invoke-virtual {p0}, Lo8/j;->f()B

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eq v0, p1, :cond_2

    .line 6
    .line 7
    invoke-static {p1}, Lwz0/p;->s(B)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    iget v0, p0, Lo8/j;->b:I

    .line 12
    .line 13
    add-int/lit8 v1, v0, -0x1

    .line 14
    .line 15
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-eq v0, v2, :cond_1

    .line 24
    .line 25
    if-gez v1, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    invoke-interface {v0, v1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    invoke-static {v0}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    :goto_0
    const-string v0, "EOF"

    .line 42
    .line 43
    :goto_1
    const-string v2, ", but had \'"

    .line 44
    .line 45
    const-string v3, "\' instead"

    .line 46
    .line 47
    const-string v4, "Expected "

    .line 48
    .line 49
    invoke-static {v4, p1, v2, v0, v3}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    const/4 v0, 0x4

    .line 54
    const/4 v2, 0x0

    .line 55
    invoke-static {p0, p1, v1, v2, v0}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 56
    .line 57
    .line 58
    throw v2

    .line 59
    :cond_2
    return v0
.end method

.method public abstract h(C)V
.end method

.method public i()J
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-virtual {v0}, Lo8/j;->C()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-virtual {v0, v1}, Lo8/j;->z(I)I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-virtual {v0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    const-string v3, "EOF"

    .line 20
    .line 21
    const/4 v4, 0x6

    .line 22
    const/4 v5, 0x0

    .line 23
    const/4 v6, 0x0

    .line 24
    if-ge v1, v2, :cond_1d

    .line 25
    .line 26
    const/4 v2, -0x1

    .line 27
    if-eq v1, v2, :cond_1d

    .line 28
    .line 29
    invoke-virtual {v0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-interface {v2, v1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    const/16 v7, 0x22

    .line 38
    .line 39
    if-ne v2, v7, :cond_1

    .line 40
    .line 41
    add-int/lit8 v1, v1, 0x1

    .line 42
    .line 43
    invoke-virtual {v0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    if-eq v1, v2, :cond_0

    .line 52
    .line 53
    const/4 v2, 0x1

    .line 54
    goto :goto_0

    .line 55
    :cond_0
    invoke-static {v0, v3, v6, v5, v4}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 56
    .line 57
    .line 58
    throw v5

    .line 59
    :cond_1
    move v2, v6

    .line 60
    :goto_0
    move v11, v1

    .line 61
    move v8, v6

    .line 62
    move v12, v8

    .line 63
    move v13, v12

    .line 64
    const-wide/16 v9, 0x0

    .line 65
    .line 66
    const-wide/16 v14, 0x0

    .line 67
    .line 68
    const-wide/16 v16, 0x0

    .line 69
    .line 70
    :goto_1
    invoke-virtual {v0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 71
    .line 72
    .line 73
    move-result-object v18

    .line 74
    invoke-interface/range {v18 .. v18}, Ljava/lang/CharSequence;->length()I

    .line 75
    .line 76
    .line 77
    move-result v7

    .line 78
    const-string v4, "Numeric value overflow"

    .line 79
    .line 80
    if-eq v11, v7, :cond_e

    .line 81
    .line 82
    invoke-virtual {v0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 83
    .line 84
    .line 85
    move-result-object v7

    .line 86
    invoke-interface {v7, v11}, Ljava/lang/CharSequence;->charAt(I)C

    .line 87
    .line 88
    .line 89
    move-result v7

    .line 90
    const/16 v5, 0x65

    .line 91
    .line 92
    if-eq v7, v5, :cond_3

    .line 93
    .line 94
    const/16 v5, 0x45

    .line 95
    .line 96
    if-ne v7, v5, :cond_2

    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_2
    move/from16 v19, v2

    .line 100
    .line 101
    const/4 v5, 0x6

    .line 102
    goto :goto_3

    .line 103
    :cond_3
    :goto_2
    if-nez v12, :cond_2

    .line 104
    .line 105
    if-eq v11, v1, :cond_4

    .line 106
    .line 107
    add-int/lit8 v11, v11, 0x1

    .line 108
    .line 109
    const/4 v4, 0x6

    .line 110
    const/4 v5, 0x0

    .line 111
    const/16 v7, 0x22

    .line 112
    .line 113
    const/4 v8, 0x1

    .line 114
    const/4 v12, 0x1

    .line 115
    goto :goto_1

    .line 116
    :cond_4
    new-instance v1, Ljava/lang/StringBuilder;

    .line 117
    .line 118
    const-string v2, "Unexpected symbol "

    .line 119
    .line 120
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    const-string v2, " in numeric literal"

    .line 127
    .line 128
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 129
    .line 130
    .line 131
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object v1

    .line 135
    const/4 v2, 0x0

    .line 136
    const/4 v5, 0x6

    .line 137
    invoke-static {v0, v1, v6, v2, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 138
    .line 139
    .line 140
    throw v2

    .line 141
    :goto_3
    const-string v2, "Unexpected symbol \'-\' in numeric literal"

    .line 142
    .line 143
    const/16 v5, 0x2d

    .line 144
    .line 145
    if-ne v7, v5, :cond_6

    .line 146
    .line 147
    if-eqz v12, :cond_6

    .line 148
    .line 149
    if-eq v11, v1, :cond_5

    .line 150
    .line 151
    add-int/lit8 v11, v11, 0x1

    .line 152
    .line 153
    move v8, v6

    .line 154
    move/from16 v2, v19

    .line 155
    .line 156
    :goto_4
    const/4 v4, 0x6

    .line 157
    const/4 v5, 0x0

    .line 158
    :goto_5
    const/16 v7, 0x22

    .line 159
    .line 160
    goto :goto_1

    .line 161
    :cond_5
    const/4 v4, 0x0

    .line 162
    const/4 v5, 0x6

    .line 163
    invoke-static {v0, v2, v6, v4, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 164
    .line 165
    .line 166
    throw v4

    .line 167
    :cond_6
    const/4 v5, 0x0

    .line 168
    const/16 v5, 0x2b

    .line 169
    .line 170
    if-ne v7, v5, :cond_8

    .line 171
    .line 172
    if-eqz v12, :cond_8

    .line 173
    .line 174
    if-eq v11, v1, :cond_7

    .line 175
    .line 176
    add-int/lit8 v11, v11, 0x1

    .line 177
    .line 178
    move/from16 v2, v19

    .line 179
    .line 180
    const/4 v4, 0x6

    .line 181
    const/4 v5, 0x0

    .line 182
    const/16 v7, 0x22

    .line 183
    .line 184
    const/4 v8, 0x1

    .line 185
    goto :goto_1

    .line 186
    :cond_7
    const-string v1, "Unexpected symbol \'+\' in numeric literal"

    .line 187
    .line 188
    const/4 v2, 0x0

    .line 189
    const/4 v5, 0x6

    .line 190
    invoke-static {v0, v1, v6, v2, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 191
    .line 192
    .line 193
    throw v2

    .line 194
    :cond_8
    move/from16 v20, v12

    .line 195
    .line 196
    const/4 v12, 0x0

    .line 197
    const/16 v5, 0x2d

    .line 198
    .line 199
    if-ne v7, v5, :cond_a

    .line 200
    .line 201
    if-ne v11, v1, :cond_9

    .line 202
    .line 203
    add-int/lit8 v11, v11, 0x1

    .line 204
    .line 205
    move-object v5, v12

    .line 206
    move/from16 v2, v19

    .line 207
    .line 208
    move/from16 v12, v20

    .line 209
    .line 210
    const/4 v4, 0x6

    .line 211
    const/16 v7, 0x22

    .line 212
    .line 213
    const/4 v13, 0x1

    .line 214
    goto/16 :goto_1

    .line 215
    .line 216
    :cond_9
    const/4 v5, 0x6

    .line 217
    invoke-static {v0, v2, v6, v12, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 218
    .line 219
    .line 220
    throw v12

    .line 221
    :cond_a
    invoke-static {v7}, Lwz0/p;->g(C)B

    .line 222
    .line 223
    .line 224
    move-result v2

    .line 225
    if-nez v2, :cond_f

    .line 226
    .line 227
    add-int/lit8 v11, v11, 0x1

    .line 228
    .line 229
    add-int/lit8 v2, v7, -0x30

    .line 230
    .line 231
    if-ltz v2, :cond_d

    .line 232
    .line 233
    const/16 v5, 0xa

    .line 234
    .line 235
    if-ge v2, v5, :cond_d

    .line 236
    .line 237
    if-eqz v20, :cond_b

    .line 238
    .line 239
    int-to-long v4, v5

    .line 240
    mul-long/2addr v9, v4

    .line 241
    int-to-long v4, v2

    .line 242
    add-long/2addr v9, v4

    .line 243
    move/from16 v2, v19

    .line 244
    .line 245
    move/from16 v12, v20

    .line 246
    .line 247
    goto :goto_4

    .line 248
    :cond_b
    int-to-long v6, v5

    .line 249
    mul-long/2addr v14, v6

    .line 250
    int-to-long v5, v2

    .line 251
    sub-long/2addr v14, v5

    .line 252
    cmp-long v2, v14, v16

    .line 253
    .line 254
    if-gtz v2, :cond_c

    .line 255
    .line 256
    move/from16 v2, v19

    .line 257
    .line 258
    move/from16 v12, v20

    .line 259
    .line 260
    const/4 v4, 0x6

    .line 261
    const/4 v5, 0x0

    .line 262
    const/4 v6, 0x0

    .line 263
    goto :goto_5

    .line 264
    :cond_c
    const/4 v2, 0x0

    .line 265
    const/4 v5, 0x6

    .line 266
    const/4 v12, 0x0

    .line 267
    invoke-static {v0, v4, v12, v2, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 268
    .line 269
    .line 270
    throw v2

    .line 271
    :cond_d
    move v12, v6

    .line 272
    const/4 v2, 0x0

    .line 273
    const/4 v5, 0x6

    .line 274
    new-instance v1, Ljava/lang/StringBuilder;

    .line 275
    .line 276
    const-string v3, "Unexpected symbol \'"

    .line 277
    .line 278
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 279
    .line 280
    .line 281
    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 282
    .line 283
    .line 284
    const-string v3, "\' in numeric literal"

    .line 285
    .line 286
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 287
    .line 288
    .line 289
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 290
    .line 291
    .line 292
    move-result-object v1

    .line 293
    invoke-static {v0, v1, v12, v2, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 294
    .line 295
    .line 296
    throw v2

    .line 297
    :cond_e
    move/from16 v19, v2

    .line 298
    .line 299
    move/from16 v20, v12

    .line 300
    .line 301
    :cond_f
    if-eq v11, v1, :cond_10

    .line 302
    .line 303
    const/4 v2, 0x1

    .line 304
    goto :goto_6

    .line 305
    :cond_10
    const/4 v2, 0x0

    .line 306
    :goto_6
    if-eq v1, v11, :cond_11

    .line 307
    .line 308
    if-eqz v13, :cond_12

    .line 309
    .line 310
    add-int/lit8 v5, v11, -0x1

    .line 311
    .line 312
    if-eq v1, v5, :cond_11

    .line 313
    .line 314
    goto :goto_7

    .line 315
    :cond_11
    const/4 v2, 0x0

    .line 316
    const/4 v5, 0x6

    .line 317
    const/4 v12, 0x0

    .line 318
    goto/16 :goto_b

    .line 319
    .line 320
    :cond_12
    :goto_7
    if-eqz v19, :cond_15

    .line 321
    .line 322
    if-eqz v2, :cond_14

    .line 323
    .line 324
    invoke-virtual {v0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 325
    .line 326
    .line 327
    move-result-object v1

    .line 328
    invoke-interface {v1, v11}, Ljava/lang/CharSequence;->charAt(I)C

    .line 329
    .line 330
    .line 331
    move-result v1

    .line 332
    const/16 v2, 0x22

    .line 333
    .line 334
    if-ne v1, v2, :cond_13

    .line 335
    .line 336
    add-int/lit8 v11, v11, 0x1

    .line 337
    .line 338
    goto :goto_8

    .line 339
    :cond_13
    const-string v1, "Expected closing quotation mark"

    .line 340
    .line 341
    const/4 v2, 0x0

    .line 342
    const/4 v5, 0x6

    .line 343
    const/4 v12, 0x0

    .line 344
    invoke-static {v0, v1, v12, v2, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 345
    .line 346
    .line 347
    throw v2

    .line 348
    :cond_14
    const/4 v2, 0x0

    .line 349
    const/4 v5, 0x6

    .line 350
    const/4 v12, 0x0

    .line 351
    invoke-static {v0, v3, v12, v2, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 352
    .line 353
    .line 354
    throw v2

    .line 355
    :cond_15
    :goto_8
    iput v11, v0, Lo8/j;->b:I

    .line 356
    .line 357
    if-eqz v20, :cond_1a

    .line 358
    .line 359
    long-to-double v1, v14

    .line 360
    const-wide/high16 v5, 0x4024000000000000L    # 10.0

    .line 361
    .line 362
    if-nez v8, :cond_16

    .line 363
    .line 364
    long-to-double v7, v9

    .line 365
    neg-double v7, v7

    .line 366
    invoke-static {v5, v6, v7, v8}, Ljava/lang/Math;->pow(DD)D

    .line 367
    .line 368
    .line 369
    move-result-wide v5

    .line 370
    goto :goto_9

    .line 371
    :cond_16
    const/4 v3, 0x1

    .line 372
    if-ne v8, v3, :cond_19

    .line 373
    .line 374
    long-to-double v7, v9

    .line 375
    invoke-static {v5, v6, v7, v8}, Ljava/lang/Math;->pow(DD)D

    .line 376
    .line 377
    .line 378
    move-result-wide v5

    .line 379
    :goto_9
    mul-double/2addr v1, v5

    .line 380
    const-wide/high16 v5, 0x43e0000000000000L    # 9.223372036854776E18

    .line 381
    .line 382
    cmpl-double v3, v1, v5

    .line 383
    .line 384
    if-gtz v3, :cond_18

    .line 385
    .line 386
    const-wide/high16 v5, -0x3c20000000000000L    # -9.223372036854776E18

    .line 387
    .line 388
    cmpg-double v3, v1, v5

    .line 389
    .line 390
    if-ltz v3, :cond_18

    .line 391
    .line 392
    invoke-static {v1, v2}, Ljava/lang/Math;->floor(D)D

    .line 393
    .line 394
    .line 395
    move-result-wide v5

    .line 396
    cmpg-double v3, v5, v1

    .line 397
    .line 398
    if-nez v3, :cond_17

    .line 399
    .line 400
    double-to-long v14, v1

    .line 401
    goto :goto_a

    .line 402
    :cond_17
    new-instance v3, Ljava/lang/StringBuilder;

    .line 403
    .line 404
    const-string v4, "Can\'t convert "

    .line 405
    .line 406
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 407
    .line 408
    .line 409
    invoke-virtual {v3, v1, v2}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 410
    .line 411
    .line 412
    const-string v1, " to Long"

    .line 413
    .line 414
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 415
    .line 416
    .line 417
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 418
    .line 419
    .line 420
    move-result-object v1

    .line 421
    const/4 v2, 0x0

    .line 422
    const/4 v5, 0x6

    .line 423
    const/4 v12, 0x0

    .line 424
    invoke-static {v0, v1, v12, v2, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 425
    .line 426
    .line 427
    throw v2

    .line 428
    :cond_18
    const/4 v2, 0x0

    .line 429
    const/4 v5, 0x6

    .line 430
    const/4 v12, 0x0

    .line 431
    invoke-static {v0, v4, v12, v2, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 432
    .line 433
    .line 434
    throw v2

    .line 435
    :cond_19
    new-instance v0, La8/r0;

    .line 436
    .line 437
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 438
    .line 439
    .line 440
    throw v0

    .line 441
    :cond_1a
    :goto_a
    if-eqz v13, :cond_1b

    .line 442
    .line 443
    return-wide v14

    .line 444
    :cond_1b
    const-wide/high16 v1, -0x8000000000000000L

    .line 445
    .line 446
    cmp-long v1, v14, v1

    .line 447
    .line 448
    if-eqz v1, :cond_1c

    .line 449
    .line 450
    neg-long v0, v14

    .line 451
    return-wide v0

    .line 452
    :cond_1c
    const/4 v2, 0x0

    .line 453
    const/4 v5, 0x6

    .line 454
    const/4 v12, 0x0

    .line 455
    invoke-static {v0, v4, v12, v2, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 456
    .line 457
    .line 458
    throw v2

    .line 459
    :goto_b
    const-string v1, "Expected numeric literal"

    .line 460
    .line 461
    invoke-static {v0, v1, v12, v2, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 462
    .line 463
    .line 464
    throw v2

    .line 465
    :cond_1d
    move-object v2, v5

    .line 466
    move v12, v6

    .line 467
    move v5, v4

    .line 468
    invoke-static {v0, v3, v12, v2, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 469
    .line 470
    .line 471
    throw v2
.end method

.method public j()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object v0, p0, Lo8/j;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    iput-object v1, p0, Lo8/j;->d:Ljava/lang/Object;

    .line 12
    .line 13
    return-object v0

    .line 14
    :cond_0
    invoke-virtual {p0}, Lo8/j;->e()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method

.method public k(Ljava/lang/CharSequence;II)Ljava/lang/String;
    .locals 9

    .line 1
    const-string v0, "source"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p3}, Ljava/lang/CharSequence;->charAt(I)C

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v1, 0x0

    .line 11
    move v2, v1

    .line 12
    :goto_0
    const/16 v3, 0x22

    .line 13
    .line 14
    const/4 v4, 0x1

    .line 15
    if-eq v0, v3, :cond_8

    .line 16
    .line 17
    const/16 v3, 0x5c

    .line 18
    .line 19
    const/4 v5, 0x4

    .line 20
    const-string v6, "Unexpected EOF"

    .line 21
    .line 22
    const/4 v7, 0x0

    .line 23
    const/4 v8, -0x1

    .line 24
    if-ne v0, v3, :cond_5

    .line 25
    .line 26
    invoke-virtual {p0, p2, p3}, Lo8/j;->b(II)V

    .line 27
    .line 28
    .line 29
    add-int/lit8 p3, p3, 0x1

    .line 30
    .line 31
    invoke-virtual {p0, p3}, Lo8/j;->z(I)I

    .line 32
    .line 33
    .line 34
    move-result p2

    .line 35
    const/4 p3, 0x6

    .line 36
    if-eq p2, v8, :cond_4

    .line 37
    .line 38
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    add-int/lit8 v2, p2, 0x1

    .line 43
    .line 44
    invoke-interface {v0, p2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 45
    .line 46
    .line 47
    move-result p2

    .line 48
    const/16 v0, 0x75

    .line 49
    .line 50
    if-ne p2, v0, :cond_0

    .line 51
    .line 52
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 53
    .line 54
    .line 55
    move-result-object p2

    .line 56
    invoke-virtual {p0, v2, p2}, Lo8/j;->a(ILjava/lang/CharSequence;)I

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    goto :goto_2

    .line 61
    :cond_0
    if-ge p2, v0, :cond_1

    .line 62
    .line 63
    sget-object v0, Lwz0/g;->a:[C

    .line 64
    .line 65
    aget-char v0, v0, p2

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_1
    move v0, v1

    .line 69
    :goto_1
    if-eqz v0, :cond_3

    .line 70
    .line 71
    iget-object p2, p0, Lo8/j;->e:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast p2, Ljava/lang/StringBuilder;

    .line 74
    .line 75
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    :goto_2
    invoke-virtual {p0, v2}, Lo8/j;->z(I)I

    .line 79
    .line 80
    .line 81
    move-result p2

    .line 82
    if-eq p2, v8, :cond_2

    .line 83
    .line 84
    :goto_3
    move p3, p2

    .line 85
    move v2, v4

    .line 86
    goto :goto_4

    .line 87
    :cond_2
    invoke-static {p0, v6, p2, v7, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 88
    .line 89
    .line 90
    throw v7

    .line 91
    :cond_3
    new-instance p1, Ljava/lang/StringBuilder;

    .line 92
    .line 93
    const-string v0, "Invalid escaped char \'"

    .line 94
    .line 95
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    const/16 p2, 0x27

    .line 102
    .line 103
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    invoke-static {p0, p1, v1, v7, p3}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 111
    .line 112
    .line 113
    throw v7

    .line 114
    :cond_4
    const-string p1, "Expected escape sequence to continue, got EOF"

    .line 115
    .line 116
    invoke-static {p0, p1, v1, v7, p3}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 117
    .line 118
    .line 119
    throw v7

    .line 120
    :cond_5
    add-int/lit8 p3, p3, 0x1

    .line 121
    .line 122
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 123
    .line 124
    .line 125
    move-result v0

    .line 126
    if-lt p3, v0, :cond_7

    .line 127
    .line 128
    invoke-virtual {p0, p2, p3}, Lo8/j;->b(II)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {p0, p3}, Lo8/j;->z(I)I

    .line 132
    .line 133
    .line 134
    move-result p2

    .line 135
    if-eq p2, v8, :cond_6

    .line 136
    .line 137
    goto :goto_3

    .line 138
    :cond_6
    invoke-static {p0, v6, p2, v7, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 139
    .line 140
    .line 141
    throw v7

    .line 142
    :cond_7
    :goto_4
    invoke-interface {p1, p3}, Ljava/lang/CharSequence;->charAt(I)C

    .line 143
    .line 144
    .line 145
    move-result v0

    .line 146
    goto/16 :goto_0

    .line 147
    .line 148
    :cond_8
    if-nez v2, :cond_9

    .line 149
    .line 150
    invoke-virtual {p0, p2, p3}, Lo8/j;->D(II)Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    goto :goto_5

    .line 155
    :cond_9
    invoke-virtual {p0, p2, p3}, Lo8/j;->n(II)Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    :goto_5
    add-int/2addr p3, v4

    .line 160
    iput p3, p0, Lo8/j;->b:I

    .line 161
    .line 162
    return-object p1
.end method

.method public l()Ljava/lang/String;
    .locals 6

    .line 1
    iget-object v0, p0, Lo8/j;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iput-object v1, p0, Lo8/j;->d:Ljava/lang/Object;

    .line 12
    .line 13
    return-object v0

    .line 14
    :cond_0
    invoke-virtual {p0}, Lo8/j;->C()I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-ge v0, v2, :cond_7

    .line 27
    .line 28
    const/4 v2, -0x1

    .line 29
    if-eq v0, v2, :cond_7

    .line 30
    .line 31
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    invoke-interface {v3, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    invoke-static {v3}, Lwz0/p;->g(C)B

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    const/4 v4, 0x1

    .line 44
    if-ne v3, v4, :cond_1

    .line 45
    .line 46
    invoke-virtual {p0}, Lo8/j;->j()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0

    .line 51
    :cond_1
    const/4 v5, 0x0

    .line 52
    if-nez v3, :cond_6

    .line 53
    .line 54
    move v1, v5

    .line 55
    :cond_2
    :goto_0
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    invoke-interface {v3, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    invoke-static {v3}, Lwz0/p;->g(C)B

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    if-nez v3, :cond_4

    .line 68
    .line 69
    add-int/lit8 v0, v0, 0x1

    .line 70
    .line 71
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    invoke-interface {v3}, Ljava/lang/CharSequence;->length()I

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    if-lt v0, v3, :cond_2

    .line 80
    .line 81
    iget v1, p0, Lo8/j;->b:I

    .line 82
    .line 83
    invoke-virtual {p0, v1, v0}, Lo8/j;->b(II)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p0, v0}, Lo8/j;->z(I)I

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    if-ne v1, v2, :cond_3

    .line 91
    .line 92
    iput v0, p0, Lo8/j;->b:I

    .line 93
    .line 94
    invoke-virtual {p0, v5, v5}, Lo8/j;->n(II)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    return-object p0

    .line 99
    :cond_3
    move v0, v1

    .line 100
    move v1, v4

    .line 101
    goto :goto_0

    .line 102
    :cond_4
    if-nez v1, :cond_5

    .line 103
    .line 104
    iget v1, p0, Lo8/j;->b:I

    .line 105
    .line 106
    invoke-virtual {p0, v1, v0}, Lo8/j;->D(II)Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    goto :goto_1

    .line 111
    :cond_5
    iget v1, p0, Lo8/j;->b:I

    .line 112
    .line 113
    invoke-virtual {p0, v1, v0}, Lo8/j;->n(II)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    :goto_1
    iput v0, p0, Lo8/j;->b:I

    .line 118
    .line 119
    return-object v1

    .line 120
    :cond_6
    new-instance v2, Ljava/lang/StringBuilder;

    .line 121
    .line 122
    const-string v3, "Expected beginning of the string, but got "

    .line 123
    .line 124
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 128
    .line 129
    .line 130
    move-result-object v3

    .line 131
    invoke-interface {v3, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 132
    .line 133
    .line 134
    move-result v0

    .line 135
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    const/4 v2, 0x6

    .line 143
    invoke-static {p0, v0, v5, v1, v2}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 144
    .line 145
    .line 146
    throw v1

    .line 147
    :cond_7
    const-string v2, "EOF"

    .line 148
    .line 149
    const/4 v3, 0x4

    .line 150
    invoke-static {p0, v2, v0, v1, v3}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 151
    .line 152
    .line 153
    throw v1
.end method

.method public m()Ljava/lang/String;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lo8/j;->l()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "null"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    iget v2, p0, Lo8/j;->b:I

    .line 18
    .line 19
    add-int/lit8 v2, v2, -0x1

    .line 20
    .line 21
    invoke-interface {v1, v2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    const/16 v2, 0x22

    .line 26
    .line 27
    if-ne v1, v2, :cond_0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 v0, 0x0

    .line 31
    const/4 v1, 0x6

    .line 32
    const-string v2, "Unexpected \'null\' value instead of string literal"

    .line 33
    .line 34
    const/4 v3, 0x0

    .line 35
    invoke-static {p0, v2, v0, v3, v1}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 36
    .line 37
    .line 38
    throw v3

    .line 39
    :cond_1
    :goto_0
    return-object v0
.end method

.method public n(II)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lo8/j;->b(II)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lo8/j;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    const-string p2, "toString(...)"

    .line 13
    .line 14
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const/4 p2, 0x0

    .line 18
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->setLength(I)V

    .line 19
    .line 20
    .line 21
    return-object p1
.end method

.method public o()V
    .locals 0

    .line 1
    return-void
.end method

.method public p()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lo8/j;->f()B

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0xa

    .line 6
    .line 7
    if-ne v0, v1, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v1, "Expected EOF after parsing, but had "

    .line 13
    .line 14
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    iget v2, p0, Lo8/j;->b:I

    .line 22
    .line 23
    add-int/lit8 v2, v2, -0x1

    .line 24
    .line 25
    invoke-interface {v1, v2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string v1, " instead"

    .line 33
    .line 34
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    const/4 v1, 0x0

    .line 42
    const/4 v2, 0x6

    .line 43
    const/4 v3, 0x0

    .line 44
    invoke-static {p0, v0, v1, v3, v2}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 45
    .line 46
    .line 47
    throw v3
.end method

.method public q(Ljava/lang/String;ILjava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "message"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "hint"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p3}, Ljava/lang/String;->length()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    const-string p3, ""

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const-string v0, "\n"

    .line 21
    .line 22
    invoke-virtual {v0, p3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p3

    .line 26
    :goto_0
    const-string v0, " at path: "

    .line 27
    .line 28
    invoke-static {p1, v0}, Lp3/m;->q(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    iget-object v0, p0, Lo8/j;->c:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v0, Lbb/g0;

    .line 35
    .line 36
    invoke-virtual {v0}, Lbb/g0;->l()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {p1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-static {p2, p0, p1}, Lwz0/p;->c(ILjava/lang/CharSequence;Ljava/lang/String;)Lwz0/l;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    throw p0
.end method

.method public s(ILjava/lang/CharSequence;)I
    .locals 2

    .line 1
    invoke-interface {p2, p1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    const/16 p2, 0x30

    .line 6
    .line 7
    if-gt p2, p1, :cond_0

    .line 8
    .line 9
    const/16 v0, 0x3a

    .line 10
    .line 11
    if-ge p1, v0, :cond_0

    .line 12
    .line 13
    sub-int/2addr p1, p2

    .line 14
    return p1

    .line 15
    :cond_0
    const/16 p2, 0x61

    .line 16
    .line 17
    if-gt p2, p1, :cond_1

    .line 18
    .line 19
    const/16 p2, 0x67

    .line 20
    .line 21
    if-ge p1, p2, :cond_1

    .line 22
    .line 23
    add-int/lit8 p1, p1, -0x57

    .line 24
    .line 25
    return p1

    .line 26
    :cond_1
    const/16 p2, 0x41

    .line 27
    .line 28
    if-gt p2, p1, :cond_2

    .line 29
    .line 30
    const/16 p2, 0x47

    .line 31
    .line 32
    if-ge p1, p2, :cond_2

    .line 33
    .line 34
    add-int/lit8 p1, p1, -0x37

    .line 35
    .line 36
    return p1

    .line 37
    :cond_2
    new-instance p2, Ljava/lang/StringBuilder;

    .line 38
    .line 39
    const-string v0, "Invalid toHexChar char \'"

    .line 40
    .line 41
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string p1, "\' in unicode escape"

    .line 48
    .line 49
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    const/4 p2, 0x0

    .line 57
    const/4 v0, 0x6

    .line 58
    const/4 v1, 0x0

    .line 59
    invoke-static {p0, p1, p2, v1, v0}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 60
    .line 61
    .line 62
    throw v1
.end method

.method public abstract t()Ljava/lang/CharSequence;
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget v0, p0, Lo8/j;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v1, "JsonReader(source=\'"

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v1, "\', currentPosition="

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    iget p0, p0, Lo8/j;->b:I

    .line 31
    .line 32
    const/16 v1, 0x29

    .line 33
    .line 34
    invoke-static {v0, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->m(Ljava/lang/StringBuilder;IC)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public u(Lo8/p;Lo8/s;)I
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    iget-object v3, v0, Lo8/j;->d:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v3, Lo8/i;

    .line 10
    .line 11
    :goto_0
    iget-object v4, v0, Lo8/j;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v4, Lo8/f;

    .line 14
    .line 15
    invoke-static {v4}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    iget-wide v5, v4, Lo8/f;->f:J

    .line 19
    .line 20
    iget-wide v7, v4, Lo8/f;->g:J

    .line 21
    .line 22
    iget-wide v9, v4, Lo8/f;->h:J

    .line 23
    .line 24
    sub-long/2addr v7, v5

    .line 25
    iget v11, v0, Lo8/j;->b:I

    .line 26
    .line 27
    int-to-long v11, v11

    .line 28
    cmp-long v7, v7, v11

    .line 29
    .line 30
    const/4 v8, 0x0

    .line 31
    if-gtz v7, :cond_0

    .line 32
    .line 33
    iput-object v8, v0, Lo8/j;->e:Ljava/lang/Object;

    .line 34
    .line 35
    invoke-interface {v3}, Lo8/i;->j()V

    .line 36
    .line 37
    .line 38
    invoke-static {v1, v5, v6, v2}, Lo8/j;->A(Lo8/p;JLo8/s;)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    return v0

    .line 43
    :cond_0
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 44
    .line 45
    .line 46
    move-result-wide v5

    .line 47
    sub-long v5, v9, v5

    .line 48
    .line 49
    const-wide/16 v11, 0x0

    .line 50
    .line 51
    cmp-long v7, v5, v11

    .line 52
    .line 53
    if-ltz v7, :cond_6

    .line 54
    .line 55
    const-wide/32 v13, 0x40000

    .line 56
    .line 57
    .line 58
    cmp-long v7, v5, v13

    .line 59
    .line 60
    if-gtz v7, :cond_6

    .line 61
    .line 62
    long-to-int v5, v5

    .line 63
    invoke-interface {v1, v5}, Lo8/p;->n(I)V

    .line 64
    .line 65
    .line 66
    invoke-interface {v1}, Lo8/p;->e()V

    .line 67
    .line 68
    .line 69
    iget-wide v5, v4, Lo8/f;->b:J

    .line 70
    .line 71
    invoke-interface {v3, v1, v5, v6}, Lo8/i;->a(Lo8/p;J)Lo8/h;

    .line 72
    .line 73
    .line 74
    move-result-object v5

    .line 75
    iget v6, v5, Lo8/h;->a:I

    .line 76
    .line 77
    move-wide v15, v11

    .line 78
    iget-wide v11, v5, Lo8/h;->b:J

    .line 79
    .line 80
    move-wide/from16 v17, v13

    .line 81
    .line 82
    iget-wide v13, v5, Lo8/h;->c:J

    .line 83
    .line 84
    const/4 v5, -0x3

    .line 85
    if-eq v6, v5, :cond_5

    .line 86
    .line 87
    const/4 v5, -0x2

    .line 88
    if-eq v6, v5, :cond_4

    .line 89
    .line 90
    const/4 v5, -0x1

    .line 91
    if-eq v6, v5, :cond_3

    .line 92
    .line 93
    if-nez v6, :cond_2

    .line 94
    .line 95
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 96
    .line 97
    .line 98
    move-result-wide v4

    .line 99
    sub-long v4, v13, v4

    .line 100
    .line 101
    cmp-long v6, v4, v15

    .line 102
    .line 103
    if-ltz v6, :cond_1

    .line 104
    .line 105
    cmp-long v6, v4, v17

    .line 106
    .line 107
    if-gtz v6, :cond_1

    .line 108
    .line 109
    long-to-int v4, v4

    .line 110
    invoke-interface {v1, v4}, Lo8/p;->n(I)V

    .line 111
    .line 112
    .line 113
    :cond_1
    iput-object v8, v0, Lo8/j;->e:Ljava/lang/Object;

    .line 114
    .line 115
    invoke-interface {v3}, Lo8/i;->j()V

    .line 116
    .line 117
    .line 118
    invoke-static {v1, v13, v14, v2}, Lo8/j;->A(Lo8/p;JLo8/s;)I

    .line 119
    .line 120
    .line 121
    move-result v0

    .line 122
    return v0

    .line 123
    :cond_2
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 124
    .line 125
    const-string v1, "Invalid case"

    .line 126
    .line 127
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    throw v0

    .line 131
    :cond_3
    iput-wide v11, v4, Lo8/f;->e:J

    .line 132
    .line 133
    iput-wide v13, v4, Lo8/f;->g:J

    .line 134
    .line 135
    iget-wide v5, v4, Lo8/f;->b:J

    .line 136
    .line 137
    iget-wide v7, v4, Lo8/f;->d:J

    .line 138
    .line 139
    iget-wide v9, v4, Lo8/f;->f:J

    .line 140
    .line 141
    move-wide v15, v5

    .line 142
    iget-wide v5, v4, Lo8/f;->c:J

    .line 143
    .line 144
    move-wide/from16 v25, v5

    .line 145
    .line 146
    move-wide/from16 v17, v7

    .line 147
    .line 148
    move-wide/from16 v21, v9

    .line 149
    .line 150
    move-wide/from16 v19, v11

    .line 151
    .line 152
    move-wide/from16 v23, v13

    .line 153
    .line 154
    invoke-static/range {v15 .. v26}, Lo8/f;->a(JJJJJJ)J

    .line 155
    .line 156
    .line 157
    move-result-wide v5

    .line 158
    iput-wide v5, v4, Lo8/f;->h:J

    .line 159
    .line 160
    goto/16 :goto_0

    .line 161
    .line 162
    :cond_4
    move-wide v5, v11

    .line 163
    move-wide v7, v13

    .line 164
    iput-wide v5, v4, Lo8/f;->d:J

    .line 165
    .line 166
    iput-wide v7, v4, Lo8/f;->f:J

    .line 167
    .line 168
    iget-wide v9, v4, Lo8/f;->b:J

    .line 169
    .line 170
    iget-wide v11, v4, Lo8/f;->e:J

    .line 171
    .line 172
    iget-wide v13, v4, Lo8/f;->g:J

    .line 173
    .line 174
    move-wide/from16 v19, v5

    .line 175
    .line 176
    iget-wide v5, v4, Lo8/f;->c:J

    .line 177
    .line 178
    move-wide/from16 v25, v5

    .line 179
    .line 180
    move-wide/from16 v21, v7

    .line 181
    .line 182
    move-wide v15, v9

    .line 183
    move-wide/from16 v23, v13

    .line 184
    .line 185
    move-wide/from16 v17, v19

    .line 186
    .line 187
    move-wide/from16 v19, v11

    .line 188
    .line 189
    invoke-static/range {v15 .. v26}, Lo8/f;->a(JJJJJJ)J

    .line 190
    .line 191
    .line 192
    move-result-wide v5

    .line 193
    iput-wide v5, v4, Lo8/f;->h:J

    .line 194
    .line 195
    goto/16 :goto_0

    .line 196
    .line 197
    :cond_5
    iput-object v8, v0, Lo8/j;->e:Ljava/lang/Object;

    .line 198
    .line 199
    invoke-interface {v3}, Lo8/i;->j()V

    .line 200
    .line 201
    .line 202
    invoke-static {v1, v9, v10, v2}, Lo8/j;->A(Lo8/p;JLo8/s;)I

    .line 203
    .line 204
    .line 205
    move-result v0

    .line 206
    return v0

    .line 207
    :cond_6
    invoke-static {v1, v9, v10, v2}, Lo8/j;->A(Lo8/p;JLo8/s;)I

    .line 208
    .line 209
    .line 210
    move-result v0

    .line 211
    return v0
.end method

.method public abstract w(Ljava/lang/String;Z)Ljava/lang/String;
.end method

.method public x()B
    .locals 5

    .line 1
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget v1, p0, Lo8/j;->b:I

    .line 6
    .line 7
    :goto_0
    invoke-virtual {p0, v1}, Lo8/j;->z(I)I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    const/4 v2, -0x1

    .line 12
    const/16 v3, 0xa

    .line 13
    .line 14
    if-eq v1, v2, :cond_1

    .line 15
    .line 16
    invoke-interface {v0, v1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    const/16 v4, 0x9

    .line 21
    .line 22
    if-eq v2, v4, :cond_0

    .line 23
    .line 24
    if-eq v2, v3, :cond_0

    .line 25
    .line 26
    const/16 v3, 0xd

    .line 27
    .line 28
    if-eq v2, v3, :cond_0

    .line 29
    .line 30
    const/16 v3, 0x20

    .line 31
    .line 32
    if-eq v2, v3, :cond_0

    .line 33
    .line 34
    iput v1, p0, Lo8/j;->b:I

    .line 35
    .line 36
    invoke-static {v2}, Lwz0/p;->g(C)B

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    return p0

    .line 41
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    iput v1, p0, Lo8/j;->b:I

    .line 45
    .line 46
    return v3
.end method

.method public y(Z)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lo8/j;->x()B

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    if-eqz p1, :cond_1

    .line 7
    .line 8
    if-eq v0, v1, :cond_0

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    invoke-virtual {p0}, Lo8/j;->l()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    goto :goto_1

    .line 18
    :cond_1
    if-eq v0, v1, :cond_2

    .line 19
    .line 20
    :goto_0
    const/4 p0, 0x0

    .line 21
    return-object p0

    .line 22
    :cond_2
    invoke-virtual {p0}, Lo8/j;->j()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    :goto_1
    iput-object p1, p0, Lo8/j;->d:Ljava/lang/Object;

    .line 27
    .line 28
    return-object p1
.end method

.method public abstract z(I)I
.end method
