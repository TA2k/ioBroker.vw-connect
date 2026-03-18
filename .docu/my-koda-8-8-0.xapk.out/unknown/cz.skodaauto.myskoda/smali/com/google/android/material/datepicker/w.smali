.class public final Lcom/google/android/material/datepicker/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld6/s;
.implements Li9/c;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public f:I

.field public g:I

.field public h:I

.field public i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    .line 1
    const/4 v0, 0x3

    iput v0, p0, Lcom/google/android/material/datepicker/w;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(IIIII[B)V
    .locals 0

    const/4 p1, 0x4

    iput p1, p0, Lcom/google/android/material/datepicker/w;->d:I

    .line 33
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 34
    iput p2, p0, Lcom/google/android/material/datepicker/w;->e:I

    .line 35
    iput p3, p0, Lcom/google/android/material/datepicker/w;->f:I

    .line 36
    iput p4, p0, Lcom/google/android/material/datepicker/w;->g:I

    .line 37
    iput p5, p0, Lcom/google/android/material/datepicker/w;->h:I

    .line 38
    iput-object p6, p0, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/view/View;IIII)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lcom/google/android/material/datepicker/w;->d:I

    .line 39
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p2, p0, Lcom/google/android/material/datepicker/w;->e:I

    iput-object p1, p0, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    iput p3, p0, Lcom/google/android/material/datepicker/w;->f:I

    iput p4, p0, Lcom/google/android/material/datepicker/w;->g:I

    iput p5, p0, Lcom/google/android/material/datepicker/w;->h:I

    return-void
.end method

.method public constructor <init>(Lg4/g;J)V
    .locals 3

    const/4 v0, 0x2

    iput v0, p0, Lcom/google/android/material/datepicker/w;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    new-instance v0, Li4/c;

    .line 4
    iget-object p1, p1, Lg4/g;->e:Ljava/lang/String;

    const/4 v1, 0x4

    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v2, v1}, Li4/c;-><init>(BI)V

    iput-object p1, v0, Li4/c;->d:Ljava/lang/Object;

    const/4 v1, -0x1

    .line 6
    iput v1, v0, Li4/c;->b:I

    .line 7
    iput v1, v0, Li4/c;->c:I

    .line 8
    iput-object v0, p0, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 9
    invoke-static {p2, p3}, Lg4/o0;->f(J)I

    move-result v0

    iput v0, p0, Lcom/google/android/material/datepicker/w;->e:I

    .line 10
    invoke-static {p2, p3}, Lg4/o0;->e(J)I

    move-result v0

    iput v0, p0, Lcom/google/android/material/datepicker/w;->f:I

    .line 11
    iput v1, p0, Lcom/google/android/material/datepicker/w;->g:I

    .line 12
    iput v1, p0, Lcom/google/android/material/datepicker/w;->h:I

    .line 13
    invoke-static {p2, p3}, Lg4/o0;->f(J)I

    move-result p0

    .line 14
    invoke-static {p2, p3}, Lg4/o0;->e(J)I

    move-result p2

    .line 15
    const-string p3, ") offset is outside of text region "

    if-ltz p0, :cond_2

    .line 16
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v0

    if-gt p0, v0, :cond_2

    if-ltz p2, :cond_1

    .line 17
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v0

    if-gt p2, v0, :cond_1

    if-gt p0, p2, :cond_0

    return-void

    .line 18
    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p3, "Do not set reversed range: "

    const-string v0, " > "

    .line 19
    invoke-static {p3, v0, p0, p2}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    move-result-object p0

    .line 20
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    .line 21
    :cond_1
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 22
    const-string v0, "end ("

    .line 23
    invoke-static {v0, p2, p3}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p2

    .line 24
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result p1

    .line 25
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 27
    :cond_2
    new-instance p2, Ljava/lang/IndexOutOfBoundsException;

    .line 28
    const-string v0, "start ("

    .line 29
    invoke-static {v0, p0, p3}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p0

    .line 30
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result p1

    .line 31
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    .line 32
    invoke-direct {p2, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw p2
.end method

.method public constructor <init>(Lx7/d;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lcom/google/android/material/datepicker/w;->d:I

    .line 40
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 41
    iget-object p1, p1, Lx7/d;->f:Lw7/p;

    iput-object p1, p0, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    const/16 v0, 0xc

    .line 42
    invoke-virtual {p1, v0}, Lw7/p;->I(I)V

    .line 43
    invoke-virtual {p1}, Lw7/p;->A()I

    move-result v0

    and-int/lit16 v0, v0, 0xff

    iput v0, p0, Lcom/google/android/material/datepicker/w;->f:I

    .line 44
    invoke-virtual {p1}, Lw7/p;->A()I

    move-result p1

    iput p1, p0, Lcom/google/android/material/datepicker/w;->e:I

    return-void
.end method


# virtual methods
.method public a(II)V
    .locals 4

    .line 1
    invoke-static {p1, p2}, Lg4/f0;->b(II)J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iget-object v2, p0, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Li4/c;

    .line 8
    .line 9
    const-string v3, ""

    .line 10
    .line 11
    invoke-virtual {v2, p1, p2, v3}, Li4/c;->O(IILjava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget p1, p0, Lcom/google/android/material/datepicker/w;->e:I

    .line 15
    .line 16
    iget p2, p0, Lcom/google/android/material/datepicker/w;->f:I

    .line 17
    .line 18
    invoke-static {p1, p2}, Lg4/f0;->b(II)J

    .line 19
    .line 20
    .line 21
    move-result-wide p1

    .line 22
    invoke-static {p1, p2, v0, v1}, Llp/pe;->b(JJ)J

    .line 23
    .line 24
    .line 25
    move-result-wide p1

    .line 26
    invoke-static {p1, p2}, Lg4/o0;->f(J)I

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    invoke-virtual {p0, v2}, Lcom/google/android/material/datepicker/w;->i(I)V

    .line 31
    .line 32
    .line 33
    invoke-static {p1, p2}, Lg4/o0;->e(J)I

    .line 34
    .line 35
    .line 36
    move-result p1

    .line 37
    invoke-virtual {p0, p1}, Lcom/google/android/material/datepicker/w;->h(I)V

    .line 38
    .line 39
    .line 40
    iget p1, p0, Lcom/google/android/material/datepicker/w;->g:I

    .line 41
    .line 42
    const/4 p2, -0x1

    .line 43
    if-eq p1, p2, :cond_1

    .line 44
    .line 45
    iget v2, p0, Lcom/google/android/material/datepicker/w;->h:I

    .line 46
    .line 47
    invoke-static {p1, v2}, Lg4/f0;->b(II)J

    .line 48
    .line 49
    .line 50
    move-result-wide v2

    .line 51
    invoke-static {v2, v3, v0, v1}, Llp/pe;->b(JJ)J

    .line 52
    .line 53
    .line 54
    move-result-wide v0

    .line 55
    invoke-static {v0, v1}, Lg4/o0;->c(J)Z

    .line 56
    .line 57
    .line 58
    move-result p1

    .line 59
    if-eqz p1, :cond_0

    .line 60
    .line 61
    iput p2, p0, Lcom/google/android/material/datepicker/w;->g:I

    .line 62
    .line 63
    iput p2, p0, Lcom/google/android/material/datepicker/w;->h:I

    .line 64
    .line 65
    return-void

    .line 66
    :cond_0
    invoke-static {v0, v1}, Lg4/o0;->f(J)I

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    iput p1, p0, Lcom/google/android/material/datepicker/w;->g:I

    .line 71
    .line 72
    invoke-static {v0, v1}, Lg4/o0;->e(J)I

    .line 73
    .line 74
    .line 75
    move-result p1

    .line 76
    iput p1, p0, Lcom/google/android/material/datepicker/w;->h:I

    .line 77
    .line 78
    :cond_1
    return-void
.end method

.method public b(I)C
    .locals 4

    .line 1
    iget-object p0, p0, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Li4/c;

    .line 4
    .line 5
    iget-object v0, p0, Li4/c;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Landroidx/collection/h;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Li4/c;->d:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Ljava/lang/String;

    .line 14
    .line 15
    invoke-virtual {p0, p1}, Ljava/lang/String;->charAt(I)C

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :cond_0
    iget v1, p0, Li4/c;->b:I

    .line 21
    .line 22
    if-ge p1, v1, :cond_1

    .line 23
    .line 24
    iget-object p0, p0, Li4/c;->d:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p0, Ljava/lang/String;

    .line 27
    .line 28
    invoke-virtual {p0, p1}, Ljava/lang/String;->charAt(I)C

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    return p0

    .line 33
    :cond_1
    iget v1, v0, Landroidx/collection/h;->e:I

    .line 34
    .line 35
    invoke-virtual {v0}, Landroidx/collection/h;->d()I

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    sub-int/2addr v1, v2

    .line 40
    iget v2, p0, Li4/c;->b:I

    .line 41
    .line 42
    add-int v3, v1, v2

    .line 43
    .line 44
    if-ge p1, v3, :cond_3

    .line 45
    .line 46
    sub-int/2addr p1, v2

    .line 47
    iget p0, v0, Landroidx/collection/h;->f:I

    .line 48
    .line 49
    if-ge p1, p0, :cond_2

    .line 50
    .line 51
    iget-object p0, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast p0, [C

    .line 54
    .line 55
    aget-char p0, p0, p1

    .line 56
    .line 57
    return p0

    .line 58
    :cond_2
    iget-object v1, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v1, [C

    .line 61
    .line 62
    sub-int/2addr p1, p0

    .line 63
    iget p0, v0, Landroidx/collection/h;->g:I

    .line 64
    .line 65
    add-int/2addr p1, p0

    .line 66
    aget-char p0, v1, p1

    .line 67
    .line 68
    return p0

    .line 69
    :cond_3
    iget-object v0, p0, Li4/c;->d:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v0, Ljava/lang/String;

    .line 72
    .line 73
    iget p0, p0, Li4/c;->c:I

    .line 74
    .line 75
    sub-int/2addr v1, p0

    .line 76
    add-int/2addr v1, v2

    .line 77
    sub-int/2addr p1, v1

    .line 78
    invoke-virtual {v0, p1}, Ljava/lang/String;->charAt(I)C

    .line 79
    .line 80
    .line 81
    move-result p0

    .line 82
    return p0
.end method

.method public c()Lg4/o0;
    .locals 2

    .line 1
    iget v0, p0, Lcom/google/android/material/datepicker/w;->g:I

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    if-eq v0, v1, :cond_0

    .line 5
    .line 6
    iget p0, p0, Lcom/google/android/material/datepicker/w;->h:I

    .line 7
    .line 8
    invoke-static {v0, p0}, Lg4/f0;->b(II)J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    new-instance p0, Lg4/o0;

    .line 13
    .line 14
    invoke-direct {p0, v0, v1}, Lg4/o0;-><init>(J)V

    .line 15
    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return-object p0
.end method

.method public d()J
    .locals 5

    .line 1
    iget v0, p0, Lcom/google/android/material/datepicker/w;->g:I

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v1, p0, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, [J

    .line 8
    .line 9
    iget v2, p0, Lcom/google/android/material/datepicker/w;->e:I

    .line 10
    .line 11
    aget-wide v3, v1, v2

    .line 12
    .line 13
    add-int/lit8 v2, v2, 0x1

    .line 14
    .line 15
    iget v1, p0, Lcom/google/android/material/datepicker/w;->h:I

    .line 16
    .line 17
    and-int/2addr v1, v2

    .line 18
    iput v1, p0, Lcom/google/android/material/datepicker/w;->e:I

    .line 19
    .line 20
    add-int/lit8 v0, v0, -0x1

    .line 21
    .line 22
    iput v0, p0, Lcom/google/android/material/datepicker/w;->g:I

    .line 23
    .line 24
    return-wide v3

    .line 25
    :cond_0
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 28
    .line 29
    .line 30
    throw p0
.end method

.method public e(IILjava/lang/String;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Li4/c;

    .line 4
    .line 5
    const-string v1, ") offset is outside of text region "

    .line 6
    .line 7
    if-ltz p1, :cond_2

    .line 8
    .line 9
    invoke-virtual {v0}, Li4/c;->s()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    if-gt p1, v2, :cond_2

    .line 14
    .line 15
    if-ltz p2, :cond_1

    .line 16
    .line 17
    invoke-virtual {v0}, Li4/c;->s()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-gt p2, v2, :cond_1

    .line 22
    .line 23
    if-gt p1, p2, :cond_0

    .line 24
    .line 25
    invoke-virtual {v0, p1, p2, p3}, Li4/c;->O(IILjava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p3}, Ljava/lang/String;->length()I

    .line 29
    .line 30
    .line 31
    move-result p2

    .line 32
    add-int/2addr p2, p1

    .line 33
    invoke-virtual {p0, p2}, Lcom/google/android/material/datepicker/w;->i(I)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p3}, Ljava/lang/String;->length()I

    .line 37
    .line 38
    .line 39
    move-result p2

    .line 40
    add-int/2addr p2, p1

    .line 41
    invoke-virtual {p0, p2}, Lcom/google/android/material/datepicker/w;->h(I)V

    .line 42
    .line 43
    .line 44
    const/4 p1, -0x1

    .line 45
    iput p1, p0, Lcom/google/android/material/datepicker/w;->g:I

    .line 46
    .line 47
    iput p1, p0, Lcom/google/android/material/datepicker/w;->h:I

    .line 48
    .line 49
    return-void

    .line 50
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 51
    .line 52
    const-string p3, "Do not set reversed range: "

    .line 53
    .line 54
    const-string v0, " > "

    .line 55
    .line 56
    invoke-static {p3, v0, p1, p2}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    throw p0

    .line 64
    :cond_1
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 65
    .line 66
    const-string p1, "end ("

    .line 67
    .line 68
    invoke-static {p1, p2, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    invoke-virtual {v0}, Li4/c;->s()I

    .line 73
    .line 74
    .line 75
    move-result p2

    .line 76
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw p0

    .line 87
    :cond_2
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 88
    .line 89
    const-string p2, "start ("

    .line 90
    .line 91
    invoke-static {p2, p1, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    invoke-virtual {v0}, Li4/c;->s()I

    .line 96
    .line 97
    .line 98
    move-result p2

    .line 99
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    throw p0
.end method

.method public f(II)V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Li4/c;

    .line 4
    .line 5
    const-string v1, ") offset is outside of text region "

    .line 6
    .line 7
    if-ltz p1, :cond_2

    .line 8
    .line 9
    invoke-virtual {v0}, Li4/c;->s()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    if-gt p1, v2, :cond_2

    .line 14
    .line 15
    if-ltz p2, :cond_1

    .line 16
    .line 17
    invoke-virtual {v0}, Li4/c;->s()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-gt p2, v2, :cond_1

    .line 22
    .line 23
    if-ge p1, p2, :cond_0

    .line 24
    .line 25
    iput p1, p0, Lcom/google/android/material/datepicker/w;->g:I

    .line 26
    .line 27
    iput p2, p0, Lcom/google/android/material/datepicker/w;->h:I

    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 31
    .line 32
    const-string v0, "Do not set reversed or empty range: "

    .line 33
    .line 34
    const-string v1, " > "

    .line 35
    .line 36
    invoke-static {v0, v1, p1, p2}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 45
    .line 46
    const-string p1, "end ("

    .line 47
    .line 48
    invoke-static {p1, p2, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    invoke-virtual {v0}, Li4/c;->s()I

    .line 53
    .line 54
    .line 55
    move-result p2

    .line 56
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw p0

    .line 67
    :cond_2
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 68
    .line 69
    const-string p2, "start ("

    .line 70
    .line 71
    invoke-static {p2, p1, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    invoke-virtual {v0}, Li4/c;->s()I

    .line 76
    .line 77
    .line 78
    move-result p2

    .line 79
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    throw p0
.end method

.method public g(II)V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Li4/c;

    .line 4
    .line 5
    const-string v1, ") offset is outside of text region "

    .line 6
    .line 7
    if-ltz p1, :cond_2

    .line 8
    .line 9
    invoke-virtual {v0}, Li4/c;->s()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    if-gt p1, v2, :cond_2

    .line 14
    .line 15
    if-ltz p2, :cond_1

    .line 16
    .line 17
    invoke-virtual {v0}, Li4/c;->s()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-gt p2, v2, :cond_1

    .line 22
    .line 23
    if-gt p1, p2, :cond_0

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Lcom/google/android/material/datepicker/w;->i(I)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, p2}, Lcom/google/android/material/datepicker/w;->h(I)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 33
    .line 34
    const-string v0, "Do not set reversed range: "

    .line 35
    .line 36
    const-string v1, " > "

    .line 37
    .line 38
    invoke-static {v0, v1, p1, p2}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw p0

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 47
    .line 48
    const-string p1, "end ("

    .line 49
    .line 50
    invoke-static {p1, p2, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    invoke-virtual {v0}, Li4/c;->s()I

    .line 55
    .line 56
    .line 57
    move-result p2

    .line 58
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :cond_2
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 70
    .line 71
    const-string p2, "start ("

    .line 72
    .line 73
    invoke-static {p2, p1, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    invoke-virtual {v0}, Li4/c;->s()I

    .line 78
    .line 79
    .line 80
    move-result p2

    .line 81
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    throw p0
.end method

.method public h(I)V
    .locals 2

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    goto :goto_0

    .line 5
    :cond_0
    const/4 v0, 0x0

    .line 6
    :goto_0
    if-nez v0, :cond_1

    .line 7
    .line 8
    new-instance v0, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v1, "Cannot set selectionEnd to a negative value: "

    .line 11
    .line 12
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-static {v0}, Lm4/a;->a(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    :cond_1
    iput p1, p0, Lcom/google/android/material/datepicker/w;->f:I

    .line 26
    .line 27
    return-void
.end method

.method public i(I)V
    .locals 2

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    goto :goto_0

    .line 5
    :cond_0
    const/4 v0, 0x0

    .line 6
    :goto_0
    if-nez v0, :cond_1

    .line 7
    .line 8
    new-instance v0, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v1, "Cannot set selectionStart to a negative value: "

    .line 11
    .line 12
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-static {v0}, Lm4/a;->a(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    :cond_1
    iput p1, p0, Lcom/google/android/material/datepicker/w;->e:I

    .line 26
    .line 27
    return-void
.end method

.method public j()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lw7/p;

    .line 4
    .line 5
    iget v1, p0, Lcom/google/android/material/datepicker/w;->f:I

    .line 6
    .line 7
    const/16 v2, 0x8

    .line 8
    .line 9
    if-ne v1, v2, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0}, Lw7/p;->w()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :cond_0
    const/16 v2, 0x10

    .line 17
    .line 18
    if-ne v1, v2, :cond_1

    .line 19
    .line 20
    invoke-virtual {v0}, Lw7/p;->C()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    return p0

    .line 25
    :cond_1
    iget v1, p0, Lcom/google/android/material/datepicker/w;->g:I

    .line 26
    .line 27
    add-int/lit8 v2, v1, 0x1

    .line 28
    .line 29
    iput v2, p0, Lcom/google/android/material/datepicker/w;->g:I

    .line 30
    .line 31
    rem-int/lit8 v1, v1, 0x2

    .line 32
    .line 33
    if-nez v1, :cond_2

    .line 34
    .line 35
    invoke-virtual {v0}, Lw7/p;->w()I

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    iput v0, p0, Lcom/google/android/material/datepicker/w;->h:I

    .line 40
    .line 41
    and-int/lit16 p0, v0, 0xf0

    .line 42
    .line 43
    shr-int/lit8 p0, p0, 0x4

    .line 44
    .line 45
    return p0

    .line 46
    :cond_2
    iget p0, p0, Lcom/google/android/material/datepicker/w;->h:I

    .line 47
    .line 48
    and-int/lit8 p0, p0, 0xf

    .line 49
    .line 50
    return p0
.end method

.method public n()I
    .locals 0

    .line 1
    const/4 p0, -0x1

    .line 2
    return p0
.end method

.method public onApplyWindowInsets(Landroid/view/View;Ld6/w1;)Ld6/w1;
    .locals 4

    .line 1
    iget-object p1, p0, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p1, Landroid/view/View;

    .line 4
    .line 5
    const/16 v0, 0x207

    .line 6
    .line 7
    iget-object v1, p2, Ld6/w1;->a:Ld6/s1;

    .line 8
    .line 9
    invoke-virtual {v1, v0}, Ld6/s1;->g(I)Ls5/b;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget v1, p0, Lcom/google/android/material/datepicker/w;->e:I

    .line 14
    .line 15
    if-ltz v1, :cond_0

    .line 16
    .line 17
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    iget v3, v0, Ls5/b;->b:I

    .line 22
    .line 23
    add-int/2addr v1, v3

    .line 24
    iput v1, v2, Landroid/view/ViewGroup$LayoutParams;->height:I

    .line 25
    .line 26
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-virtual {p1, v1}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 31
    .line 32
    .line 33
    :cond_0
    iget v1, p0, Lcom/google/android/material/datepicker/w;->f:I

    .line 34
    .line 35
    iget v2, v0, Ls5/b;->a:I

    .line 36
    .line 37
    add-int/2addr v1, v2

    .line 38
    iget v2, p0, Lcom/google/android/material/datepicker/w;->g:I

    .line 39
    .line 40
    iget v3, v0, Ls5/b;->b:I

    .line 41
    .line 42
    add-int/2addr v2, v3

    .line 43
    iget p0, p0, Lcom/google/android/material/datepicker/w;->h:I

    .line 44
    .line 45
    iget v0, v0, Ls5/b;->c:I

    .line 46
    .line 47
    add-int/2addr p0, v0

    .line 48
    invoke-virtual {p1}, Landroid/view/View;->getPaddingBottom()I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    invoke-virtual {p1, v1, v2, p0, v0}, Landroid/view/View;->setPadding(IIII)V

    .line 53
    .line 54
    .line 55
    return-object p2
.end method

.method public p()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/material/datepicker/w;->e:I

    .line 2
    .line 3
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/material/datepicker/w;->d:I

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
    iget-object p0, p0, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Li4/c;

    .line 14
    .line 15
    invoke-virtual {p0}, Li4/c;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method
