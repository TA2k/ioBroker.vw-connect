.class public final Lw3/d;
.super Lh/w;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static f:Lw3/d;

.field public static final g:Lr4/j;

.field public static final h:Lr4/j;


# instance fields
.field public d:Lg4/l0;

.field public e:Ld4/q;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lr4/j;->e:Lr4/j;

    .line 2
    .line 3
    sput-object v0, Lw3/d;->g:Lr4/j;

    .line 4
    .line 5
    sget-object v0, Lr4/j;->d:Lr4/j;

    .line 6
    .line 7
    sput-object v0, Lw3/d;->h:Lr4/j;

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
    :try_start_0
    iget-object v0, p0, Lw3/d;->e:Ld4/q;

    .line 25
    .line 26
    if-eqz v0, :cond_a

    .line 27
    .line 28
    invoke-virtual {v0}, Ld4/q;->g()Ld3/c;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    iget v2, v0, Ld3/c;->d:F

    .line 33
    .line 34
    iget v0, v0, Ld3/c;->b:F

    .line 35
    .line 36
    sub-float/2addr v2, v0

    .line 37
    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    .line 38
    .line 39
    .line 40
    move-result v0
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 41
    if-lez p1, :cond_2

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    const/4 p1, 0x0

    .line 45
    :goto_0
    iget-object v2, p0, Lw3/d;->d:Lg4/l0;

    .line 46
    .line 47
    const-string v3, "layoutResult"

    .line 48
    .line 49
    if-eqz v2, :cond_9

    .line 50
    .line 51
    iget-object v2, v2, Lg4/l0;->b:Lg4/o;

    .line 52
    .line 53
    invoke-virtual {v2, p1}, Lg4/o;->d(I)I

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    iget-object v4, p0, Lw3/d;->d:Lg4/l0;

    .line 58
    .line 59
    if-eqz v4, :cond_8

    .line 60
    .line 61
    iget-object v4, v4, Lg4/l0;->b:Lg4/o;

    .line 62
    .line 63
    invoke-virtual {v4, v2}, Lg4/o;->f(I)F

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    int-to-float v0, v0

    .line 68
    add-float/2addr v2, v0

    .line 69
    iget-object v0, p0, Lw3/d;->d:Lg4/l0;

    .line 70
    .line 71
    if-eqz v0, :cond_7

    .line 72
    .line 73
    if-eqz v0, :cond_6

    .line 74
    .line 75
    iget-object v0, v0, Lg4/l0;->b:Lg4/o;

    .line 76
    .line 77
    iget v4, v0, Lg4/o;->f:I

    .line 78
    .line 79
    add-int/lit8 v4, v4, -0x1

    .line 80
    .line 81
    invoke-virtual {v0, v4}, Lg4/o;->f(I)F

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    cmpg-float v0, v2, v0

    .line 86
    .line 87
    if-gez v0, :cond_4

    .line 88
    .line 89
    iget-object v0, p0, Lw3/d;->d:Lg4/l0;

    .line 90
    .line 91
    if-eqz v0, :cond_3

    .line 92
    .line 93
    iget-object v0, v0, Lg4/l0;->b:Lg4/o;

    .line 94
    .line 95
    invoke-virtual {v0, v2}, Lg4/o;->e(F)I

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    :goto_1
    add-int/lit8 v0, v0, -0x1

    .line 100
    .line 101
    goto :goto_2

    .line 102
    :cond_3
    invoke-static {v3}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    throw v1

    .line 106
    :cond_4
    iget-object v0, p0, Lw3/d;->d:Lg4/l0;

    .line 107
    .line 108
    if-eqz v0, :cond_5

    .line 109
    .line 110
    iget-object v0, v0, Lg4/l0;->b:Lg4/o;

    .line 111
    .line 112
    iget v0, v0, Lg4/o;->f:I

    .line 113
    .line 114
    goto :goto_1

    .line 115
    :goto_2
    sget-object v1, Lw3/d;->h:Lr4/j;

    .line 116
    .line 117
    invoke-virtual {p0, v0, v1}, Lw3/d;->q(ILr4/j;)I

    .line 118
    .line 119
    .line 120
    move-result v0

    .line 121
    add-int/lit8 v0, v0, 0x1

    .line 122
    .line 123
    invoke-virtual {p0, p1, v0}, Lh/w;->i(II)[I

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    return-object p0

    .line 128
    :cond_5
    invoke-static {v3}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    throw v1

    .line 132
    :cond_6
    invoke-static {v3}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    throw v1

    .line 136
    :cond_7
    invoke-static {v3}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    throw v1

    .line 140
    :cond_8
    invoke-static {v3}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    throw v1

    .line 144
    :cond_9
    invoke-static {v3}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    throw v1

    .line 148
    :cond_a
    :try_start_1
    const-string p0, "node"

    .line 149
    .line 150
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    throw v1
    :try_end_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_0

    .line 154
    :catch_0
    return-object v1
.end method

.method public final m(I)[I
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
    if-gtz p1, :cond_1

    .line 14
    .line 15
    return-object v1

    .line 16
    :cond_1
    :try_start_0
    iget-object v0, p0, Lw3/d;->e:Ld4/q;

    .line 17
    .line 18
    if-eqz v0, :cond_8

    .line 19
    .line 20
    invoke-virtual {v0}, Ld4/q;->g()Ld3/c;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iget v2, v0, Ld3/c;->d:F

    .line 25
    .line 26
    iget v0, v0, Ld3/c;->b:F

    .line 27
    .line 28
    sub-float/2addr v2, v0

    .line 29
    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    .line 30
    .line 31
    .line 32
    move-result v0
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 33
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-le v2, p1, :cond_2

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    move p1, v2

    .line 45
    :goto_0
    iget-object v2, p0, Lw3/d;->d:Lg4/l0;

    .line 46
    .line 47
    const-string v3, "layoutResult"

    .line 48
    .line 49
    if-eqz v2, :cond_7

    .line 50
    .line 51
    iget-object v2, v2, Lg4/l0;->b:Lg4/o;

    .line 52
    .line 53
    invoke-virtual {v2, p1}, Lg4/o;->d(I)I

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    iget-object v4, p0, Lw3/d;->d:Lg4/l0;

    .line 58
    .line 59
    if-eqz v4, :cond_6

    .line 60
    .line 61
    iget-object v4, v4, Lg4/l0;->b:Lg4/o;

    .line 62
    .line 63
    invoke-virtual {v4, v2}, Lg4/o;->f(I)F

    .line 64
    .line 65
    .line 66
    move-result v4

    .line 67
    int-to-float v0, v0

    .line 68
    sub-float/2addr v4, v0

    .line 69
    const/4 v0, 0x0

    .line 70
    cmpl-float v0, v4, v0

    .line 71
    .line 72
    if-lez v0, :cond_4

    .line 73
    .line 74
    iget-object v0, p0, Lw3/d;->d:Lg4/l0;

    .line 75
    .line 76
    if-eqz v0, :cond_3

    .line 77
    .line 78
    iget-object v0, v0, Lg4/l0;->b:Lg4/o;

    .line 79
    .line 80
    invoke-virtual {v0, v4}, Lg4/o;->e(F)I

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    goto :goto_1

    .line 85
    :cond_3
    invoke-static {v3}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw v1

    .line 89
    :cond_4
    const/4 v0, 0x0

    .line 90
    :goto_1
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-ne p1, v1, :cond_5

    .line 99
    .line 100
    if-ge v0, v2, :cond_5

    .line 101
    .line 102
    add-int/lit8 v0, v0, 0x1

    .line 103
    .line 104
    :cond_5
    sget-object v1, Lw3/d;->g:Lr4/j;

    .line 105
    .line 106
    invoke-virtual {p0, v0, v1}, Lw3/d;->q(ILr4/j;)I

    .line 107
    .line 108
    .line 109
    move-result v0

    .line 110
    invoke-virtual {p0, v0, p1}, Lh/w;->i(II)[I

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    return-object p0

    .line 115
    :cond_6
    invoke-static {v3}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    throw v1

    .line 119
    :cond_7
    invoke-static {v3}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    throw v1

    .line 123
    :cond_8
    :try_start_1
    const-string p0, "node"

    .line 124
    .line 125
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    throw v1
    :try_end_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_0

    .line 129
    :catch_0
    return-object v1
.end method

.method public final q(ILr4/j;)I
    .locals 4

    .line 1
    iget-object v0, p0, Lw3/d;->d:Lg4/l0;

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
    iget-object v3, p0, Lw3/d;->d:Lg4/l0;

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
    iget-object p0, p0, Lw3/d;->d:Lg4/l0;

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
    iget-object p0, p0, Lw3/d;->d:Lg4/l0;

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
