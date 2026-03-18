.class public final Lw3/c;
.super Lh/w;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static e:Lw3/c;

.field public static final f:Lr4/j;

.field public static final g:Lr4/j;


# instance fields
.field public d:Lg4/l0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lr4/j;->e:Lr4/j;

    .line 2
    .line 3
    sput-object v0, Lw3/c;->f:Lr4/j;

    .line 4
    .line 5
    sget-object v0, Lr4/j;->d:Lr4/j;

    .line 6
    .line 7
    sput-object v0, Lw3/c;->g:Lr4/j;

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final e(I)[I
    .locals 5

    .line 1
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    if-gtz v0, :cond_0

    .line 11
    .line 12
    return-object v1

    .line 13
    :cond_0
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-lt p1, v0, :cond_1

    .line 22
    .line 23
    return-object v1

    .line 24
    :cond_1
    sget-object v0, Lw3/c;->f:Lr4/j;

    .line 25
    .line 26
    const-string v2, "layoutResult"

    .line 27
    .line 28
    if-gez p1, :cond_3

    .line 29
    .line 30
    iget-object p1, p0, Lw3/c;->d:Lg4/l0;

    .line 31
    .line 32
    if-eqz p1, :cond_2

    .line 33
    .line 34
    const/4 v3, 0x0

    .line 35
    iget-object p1, p1, Lg4/l0;->b:Lg4/o;

    .line 36
    .line 37
    invoke-virtual {p1, v3}, Lg4/o;->d(I)I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    goto :goto_0

    .line 42
    :cond_2
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw v1

    .line 46
    :cond_3
    iget-object v3, p0, Lw3/c;->d:Lg4/l0;

    .line 47
    .line 48
    if-eqz v3, :cond_7

    .line 49
    .line 50
    iget-object v3, v3, Lg4/l0;->b:Lg4/o;

    .line 51
    .line 52
    invoke-virtual {v3, p1}, Lg4/o;->d(I)I

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    invoke-virtual {p0, v3, v0}, Lw3/c;->q(ILr4/j;)I

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    if-ne v4, p1, :cond_4

    .line 61
    .line 62
    move p1, v3

    .line 63
    goto :goto_0

    .line 64
    :cond_4
    add-int/lit8 p1, v3, 0x1

    .line 65
    .line 66
    :goto_0
    iget-object v3, p0, Lw3/c;->d:Lg4/l0;

    .line 67
    .line 68
    if-eqz v3, :cond_6

    .line 69
    .line 70
    iget-object v2, v3, Lg4/l0;->b:Lg4/o;

    .line 71
    .line 72
    iget v2, v2, Lg4/o;->f:I

    .line 73
    .line 74
    if-lt p1, v2, :cond_5

    .line 75
    .line 76
    return-object v1

    .line 77
    :cond_5
    invoke-virtual {p0, p1, v0}, Lw3/c;->q(ILr4/j;)I

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    sget-object v1, Lw3/c;->g:Lr4/j;

    .line 82
    .line 83
    invoke-virtual {p0, p1, v1}, Lw3/c;->q(ILr4/j;)I

    .line 84
    .line 85
    .line 86
    move-result p1

    .line 87
    add-int/lit8 p1, p1, 0x1

    .line 88
    .line 89
    invoke-virtual {p0, v0, p1}, Lh/w;->i(II)[I

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    return-object p0

    .line 94
    :cond_6
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    throw v1

    .line 98
    :cond_7
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    throw v1
.end method

.method public final m(I)[I
    .locals 4

    .line 1
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    if-gtz v0, :cond_0

    .line 11
    .line 12
    return-object v1

    .line 13
    :cond_0
    if-gtz p1, :cond_1

    .line 14
    .line 15
    return-object v1

    .line 16
    :cond_1
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    sget-object v2, Lw3/c;->g:Lr4/j;

    .line 25
    .line 26
    const-string v3, "layoutResult"

    .line 27
    .line 28
    if-le p1, v0, :cond_3

    .line 29
    .line 30
    iget-object p1, p0, Lw3/c;->d:Lg4/l0;

    .line 31
    .line 32
    if-eqz p1, :cond_2

    .line 33
    .line 34
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    iget-object p1, p1, Lg4/l0;->b:Lg4/o;

    .line 43
    .line 44
    invoke-virtual {p1, v0}, Lg4/o;->d(I)I

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    goto :goto_0

    .line 49
    :cond_2
    invoke-static {v3}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw v1

    .line 53
    :cond_3
    iget-object v0, p0, Lw3/c;->d:Lg4/l0;

    .line 54
    .line 55
    if-eqz v0, :cond_6

    .line 56
    .line 57
    iget-object v0, v0, Lg4/l0;->b:Lg4/o;

    .line 58
    .line 59
    invoke-virtual {v0, p1}, Lg4/o;->d(I)I

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    invoke-virtual {p0, v0, v2}, Lw3/c;->q(ILr4/j;)I

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    add-int/lit8 v3, v3, 0x1

    .line 68
    .line 69
    if-ne v3, p1, :cond_4

    .line 70
    .line 71
    move p1, v0

    .line 72
    goto :goto_0

    .line 73
    :cond_4
    add-int/lit8 p1, v0, -0x1

    .line 74
    .line 75
    :goto_0
    if-gez p1, :cond_5

    .line 76
    .line 77
    return-object v1

    .line 78
    :cond_5
    sget-object v0, Lw3/c;->f:Lr4/j;

    .line 79
    .line 80
    invoke-virtual {p0, p1, v0}, Lw3/c;->q(ILr4/j;)I

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    invoke-virtual {p0, p1, v2}, Lw3/c;->q(ILr4/j;)I

    .line 85
    .line 86
    .line 87
    move-result p1

    .line 88
    add-int/lit8 p1, p1, 0x1

    .line 89
    .line 90
    invoke-virtual {p0, v0, p1}, Lh/w;->i(II)[I

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    return-object p0

    .line 95
    :cond_6
    invoke-static {v3}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    throw v1
.end method

.method public final q(ILr4/j;)I
    .locals 4

    .line 1
    iget-object v0, p0, Lw3/c;->d:Lg4/l0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "layoutResult"

    .line 5
    .line 6
    if-eqz v0, :cond_4

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lg4/l0;->g(I)I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    iget-object v3, p0, Lw3/c;->d:Lg4/l0;

    .line 13
    .line 14
    if-eqz v3, :cond_3

    .line 15
    .line 16
    invoke-virtual {v3, v0}, Lg4/l0;->h(I)Lr4/j;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    if-eq p2, v0, :cond_1

    .line 21
    .line 22
    iget-object p0, p0, Lw3/c;->d:Lg4/l0;

    .line 23
    .line 24
    if-eqz p0, :cond_0

    .line 25
    .line 26
    invoke-virtual {p0, p1}, Lg4/l0;->g(I)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    return p0

    .line 31
    :cond_0
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw v1

    .line 35
    :cond_1
    iget-object p0, p0, Lw3/c;->d:Lg4/l0;

    .line 36
    .line 37
    if-eqz p0, :cond_2

    .line 38
    .line 39
    const/4 p2, 0x0

    .line 40
    iget-object p0, p0, Lg4/l0;->b:Lg4/o;

    .line 41
    .line 42
    invoke-virtual {p0, p1, p2}, Lg4/o;->c(IZ)I

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    add-int/lit8 p0, p0, -0x1

    .line 47
    .line 48
    return p0

    .line 49
    :cond_2
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw v1

    .line 53
    :cond_3
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw v1

    .line 57
    :cond_4
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw v1
.end method
