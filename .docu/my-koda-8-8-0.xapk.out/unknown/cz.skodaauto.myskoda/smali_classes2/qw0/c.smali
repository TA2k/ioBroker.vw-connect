.class public final Lqw0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/CharSequence;
.implements Ljava/lang/Appendable;


# instance fields
.field public final d:Ldx0/d;

.field public e:Ljava/util/ArrayList;

.field public f:[C

.field public g:Ljava/lang/String;

.field public h:Z

.field public i:I

.field public j:I


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    sget-object v0, Lqw0/e;->a:Ldx0/d;

    .line 2
    .line 3
    const-string v1, "pool"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lqw0/c;->d:Ldx0/d;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a(I)[C
    .locals 2

    .line 1
    iget-object v0, p0, Lqw0/c;->e:Ljava/util/ArrayList;

    .line 2
    .line 3
    if-nez v0, :cond_2

    .line 4
    .line 5
    const/16 v0, 0x800

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    if-ge p1, v0, :cond_1

    .line 9
    .line 10
    iget-object v0, p0, Lqw0/c;->f:[C

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    return-object v0

    .line 15
    :cond_0
    invoke-virtual {p0, p1}, Lqw0/c;->e(I)V

    .line 16
    .line 17
    .line 18
    throw v1

    .line 19
    :cond_1
    invoke-virtual {p0, p1}, Lqw0/c;->e(I)V

    .line 20
    .line 21
    .line 22
    throw v1

    .line 23
    :cond_2
    iget-object p0, p0, Lqw0/c;->f:[C

    .line 24
    .line 25
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    array-length p0, p0

    .line 29
    div-int/2addr p1, p0

    .line 30
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    check-cast p0, [C

    .line 35
    .line 36
    return-object p0
.end method

.method public final append(C)Ljava/lang/Appendable;
    .locals 3

    .line 1
    invoke-virtual {p0}, Lqw0/c;->d()[C

    move-result-object v0

    iget-object v1, p0, Lqw0/c;->f:[C

    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    array-length v1, v1

    iget v2, p0, Lqw0/c;->i:I

    sub-int/2addr v1, v2

    aput-char p1, v0, v1

    const/4 p1, 0x0

    .line 2
    iput-object p1, p0, Lqw0/c;->g:Ljava/lang/String;

    add-int/lit8 v2, v2, -0x1

    .line 3
    iput v2, p0, Lqw0/c;->i:I

    .line 4
    iget p1, p0, Lqw0/c;->j:I

    add-int/lit8 p1, p1, 0x1

    .line 5
    iput p1, p0, Lqw0/c;->j:I

    return-object p0
.end method

.method public final append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;
    .locals 2

    if-nez p1, :cond_0

    return-object p0

    :cond_0
    const/4 v0, 0x0

    .line 14
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    move-result v1

    invoke-virtual {p0, p1, v0, v1}, Lqw0/c;->append(Ljava/lang/CharSequence;II)Ljava/lang/Appendable;

    return-object p0
.end method

.method public final append(Ljava/lang/CharSequence;II)Ljava/lang/Appendable;
    .locals 7

    if-nez p1, :cond_0

    return-object p0

    :cond_0
    move v0, p2

    :goto_0
    if-ge v0, p3, :cond_2

    .line 6
    invoke-virtual {p0}, Lqw0/c;->d()[C

    move-result-object v1

    .line 7
    array-length v2, v1

    iget v3, p0, Lqw0/c;->i:I

    sub-int/2addr v2, v3

    sub-int v4, p3, v0

    .line 8
    invoke-static {v4, v3}, Ljava/lang/Math;->min(II)I

    move-result v3

    const/4 v4, 0x0

    :goto_1
    if-ge v4, v3, :cond_1

    add-int v5, v2, v4

    add-int v6, v0, v4

    .line 9
    invoke-interface {p1, v6}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v6

    aput-char v6, v1, v5

    add-int/lit8 v4, v4, 0x1

    goto :goto_1

    :cond_1
    add-int/2addr v0, v3

    .line 10
    iget v1, p0, Lqw0/c;->i:I

    sub-int/2addr v1, v3

    iput v1, p0, Lqw0/c;->i:I

    goto :goto_0

    :cond_2
    const/4 p1, 0x0

    .line 11
    iput-object p1, p0, Lqw0/c;->g:Ljava/lang/String;

    .line 12
    iget p1, p0, Lqw0/c;->j:I

    sub-int/2addr p3, p2

    add-int/2addr p3, p1

    .line 13
    iput p3, p0, Lqw0/c;->j:I

    return-object p0
.end method

.method public final b(II)Ljava/lang/CharSequence;
    .locals 6

    .line 1
    if-ne p1, p2, :cond_0

    .line 2
    .line 3
    const-string p0, ""

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    sub-int v1, p2, p1

    .line 9
    .line 10
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 11
    .line 12
    .line 13
    rem-int/lit16 v1, p1, 0x800

    .line 14
    .line 15
    sub-int v1, p1, v1

    .line 16
    .line 17
    :goto_0
    if-ge v1, p2, :cond_2

    .line 18
    .line 19
    invoke-virtual {p0, v1}, Lqw0/c;->a(I)[C

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    const/4 v3, 0x0

    .line 24
    sub-int v4, p1, v1

    .line 25
    .line 26
    invoke-static {v3, v4}, Ljava/lang/Math;->max(II)I

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    sub-int v4, p2, v1

    .line 31
    .line 32
    const/16 v5, 0x800

    .line 33
    .line 34
    invoke-static {v4, v5}, Ljava/lang/Math;->min(II)I

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    :goto_1
    if-ge v3, v4, :cond_1

    .line 39
    .line 40
    aget-char v5, v2, v3

    .line 41
    .line 42
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    add-int/lit8 v3, v3, 0x1

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    add-int/lit16 v1, v1, 0x800

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_2
    return-object v0
.end method

.method public final c(I)C
    .locals 1

    .line 1
    invoke-virtual {p0, p1}, Lqw0/c;->a(I)[C

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lqw0/c;->f:[C

    .line 6
    .line 7
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    array-length p0, p0

    .line 11
    rem-int/2addr p1, p0

    .line 12
    aget-char p0, v0, p1

    .line 13
    .line 14
    return p0
.end method

.method public final charAt(I)C
    .locals 2

    .line 1
    if-ltz p1, :cond_1

    .line 2
    .line 3
    iget v0, p0, Lqw0/c;->j:I

    .line 4
    .line 5
    if-ge p1, v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Lqw0/c;->c(I)C

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0

    .line 12
    :cond_0
    const-string v0, "index "

    .line 13
    .line 14
    const-string v1, " is not in range [0, "

    .line 15
    .line 16
    invoke-static {v0, p1, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    iget p0, p0, Lqw0/c;->j:I

    .line 21
    .line 22
    const/16 v0, 0x29

    .line 23
    .line 24
    invoke-static {p1, p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->m(Ljava/lang/StringBuilder;IC)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 29
    .line 30
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p1

    .line 38
    :cond_1
    const-string p0, "index is negative: "

    .line 39
    .line 40
    invoke-static {p1, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 45
    .line 46
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p1
.end method

.method public final d()[C
    .locals 3

    .line 1
    iget v0, p0, Lqw0/c;->i:I

    .line 2
    .line 3
    if-nez v0, :cond_2

    .line 4
    .line 5
    iget-object v0, p0, Lqw0/c;->d:Ldx0/d;

    .line 6
    .line 7
    invoke-interface {v0}, Ldx0/d;->X()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, [C

    .line 12
    .line 13
    iget-object v1, p0, Lqw0/c;->f:[C

    .line 14
    .line 15
    iput-object v0, p0, Lqw0/c;->f:[C

    .line 16
    .line 17
    array-length v2, v0

    .line 18
    iput v2, p0, Lqw0/c;->i:I

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    iput-boolean v2, p0, Lqw0/c;->h:Z

    .line 22
    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    iget-object v2, p0, Lqw0/c;->e:Ljava/util/ArrayList;

    .line 26
    .line 27
    if-nez v2, :cond_0

    .line 28
    .line 29
    new-instance v2, Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object v2, p0, Lqw0/c;->e:Ljava/util/ArrayList;

    .line 35
    .line 36
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    :cond_0
    invoke-interface {v2, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    :cond_1
    return-object v0

    .line 43
    :cond_2
    iget-object p0, p0, Lqw0/c;->f:[C

    .line 44
    .line 45
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    return-object p0
.end method

.method public final e(I)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lqw0/c;->h:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 6
    .line 7
    const-string p1, "Buffer is already released"

    .line 8
    .line 9
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    throw p0

    .line 13
    :cond_0
    new-instance v0, Ljava/lang/IndexOutOfBoundsException;

    .line 14
    .line 15
    new-instance v1, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p1, " is not in range [0; "

    .line 24
    .line 25
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object p1, p0, Lqw0/c;->f:[C

    .line 29
    .line 30
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    array-length p1, p1

    .line 34
    iget p0, p0, Lqw0/c;->i:I

    .line 35
    .line 36
    sub-int/2addr p1, p0

    .line 37
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const/16 p0, 0x29

    .line 41
    .line 42
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-direct {v0, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    instance-of v0, p1, Ljava/lang/CharSequence;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    iget v0, p0, Lqw0/c;->j:I

    .line 8
    .line 9
    check-cast p1, Ljava/lang/CharSequence;

    .line 10
    .line 11
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-eq v0, v2, :cond_1

    .line 16
    .line 17
    :goto_0
    return v1

    .line 18
    :cond_1
    iget v0, p0, Lqw0/c;->j:I

    .line 19
    .line 20
    move v2, v1

    .line 21
    :goto_1
    if-ge v2, v0, :cond_3

    .line 22
    .line 23
    invoke-virtual {p0, v2}, Lqw0/c;->c(I)C

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    invoke-interface {p1, v2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    if-eq v3, v4, :cond_2

    .line 32
    .line 33
    return v1

    .line 34
    :cond_2
    add-int/lit8 v2, v2, 0x1

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_3
    const/4 p0, 0x1

    .line 38
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lqw0/c;->g:Ljava/lang/String;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0

    .line 10
    :cond_0
    iget v0, p0, Lqw0/c;->j:I

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    move v2, v1

    .line 14
    :goto_0
    if-ge v1, v0, :cond_1

    .line 15
    .line 16
    mul-int/lit8 v2, v2, 0x1f

    .line 17
    .line 18
    invoke-virtual {p0, v1}, Lqw0/c;->c(I)C

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    add-int/2addr v2, v3

    .line 23
    add-int/lit8 v1, v1, 0x1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    return v2
.end method

.method public final length()I
    .locals 0

    .line 1
    iget p0, p0, Lqw0/c;->j:I

    .line 2
    .line 3
    return p0
.end method

.method public final subSequence(II)Ljava/lang/CharSequence;
    .locals 2

    .line 1
    const/16 v0, 0x29

    .line 2
    .line 3
    if-gt p1, p2, :cond_2

    .line 4
    .line 5
    if-ltz p1, :cond_1

    .line 6
    .line 7
    iget v1, p0, Lqw0/c;->j:I

    .line 8
    .line 9
    if-gt p2, v1, :cond_0

    .line 10
    .line 11
    new-instance v0, Lqw0/b;

    .line 12
    .line 13
    invoke-direct {v0, p0, p1, p2}, Lqw0/b;-><init>(Lqw0/c;II)V

    .line 14
    .line 15
    .line 16
    return-object v0

    .line 17
    :cond_0
    const-string p1, "endIndex ("

    .line 18
    .line 19
    const-string v1, ") is greater than length ("

    .line 20
    .line 21
    invoke-static {p1, p2, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    iget p0, p0, Lqw0/c;->j:I

    .line 26
    .line 27
    invoke-static {p1, p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->m(Ljava/lang/StringBuilder;IC)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw p1

    .line 41
    :cond_1
    const-string p0, "startIndex is negative: "

    .line 42
    .line 43
    invoke-static {p1, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 48
    .line 49
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p1

    .line 57
    :cond_2
    new-instance p0, Ljava/lang/StringBuilder;

    .line 58
    .line 59
    const-string v1, "startIndex ("

    .line 60
    .line 61
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    const-string p1, ") should be less or equal to endIndex ("

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 83
    .line 84
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    throw p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object v0, p0, Lqw0/c;->g:Ljava/lang/String;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    iget v1, p0, Lqw0/c;->j:I

    .line 7
    .line 8
    invoke-virtual {p0, v0, v1}, Lqw0/c;->b(II)Ljava/lang/CharSequence;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    iput-object v0, p0, Lqw0/c;->g:Ljava/lang/String;

    .line 17
    .line 18
    :cond_0
    return-object v0
.end method
