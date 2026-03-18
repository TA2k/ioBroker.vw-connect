.class public final Lw3/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/translation/ViewTranslationCallback;


# static fields
.field public static final a:Lw3/d0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lw3/d0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lw3/d0;->a:Lw3/d0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onClearTranslation(Landroid/view/View;)Z
    .locals 12

    .line 1
    const-string p0, "null cannot be cast to non-null type androidx.compose.ui.platform.AndroidComposeView"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Lw3/t;

    .line 7
    .line 8
    invoke-virtual {p1}, Lw3/t;->getContentCaptureManager$ui_release()Lz2/e;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    sget-object p1, Lz2/b;->d:Lz2/b;

    .line 16
    .line 17
    iput-object p1, p0, Lz2/e;->i:Lz2/b;

    .line 18
    .line 19
    invoke-virtual {p0}, Lz2/e;->d()Landroidx/collection/p;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    iget-object p1, p0, Landroidx/collection/p;->c:[Ljava/lang/Object;

    .line 24
    .line 25
    iget-object p0, p0, Landroidx/collection/p;->a:[J

    .line 26
    .line 27
    array-length v0, p0

    .line 28
    add-int/lit8 v0, v0, -0x2

    .line 29
    .line 30
    if-ltz v0, :cond_5

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    move v2, v1

    .line 34
    :goto_0
    aget-wide v3, p0, v2

    .line 35
    .line 36
    not-long v5, v3

    .line 37
    const/4 v7, 0x7

    .line 38
    shl-long/2addr v5, v7

    .line 39
    and-long/2addr v5, v3

    .line 40
    const-wide v7, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 41
    .line 42
    .line 43
    .line 44
    .line 45
    and-long/2addr v5, v7

    .line 46
    cmp-long v5, v5, v7

    .line 47
    .line 48
    if-eqz v5, :cond_4

    .line 49
    .line 50
    sub-int v5, v2, v0

    .line 51
    .line 52
    not-int v5, v5

    .line 53
    ushr-int/lit8 v5, v5, 0x1f

    .line 54
    .line 55
    const/16 v6, 0x8

    .line 56
    .line 57
    rsub-int/lit8 v5, v5, 0x8

    .line 58
    .line 59
    move v7, v1

    .line 60
    :goto_1
    if-ge v7, v5, :cond_3

    .line 61
    .line 62
    const-wide/16 v8, 0xff

    .line 63
    .line 64
    and-long/2addr v8, v3

    .line 65
    const-wide/16 v10, 0x80

    .line 66
    .line 67
    cmp-long v8, v8, v10

    .line 68
    .line 69
    if-gez v8, :cond_2

    .line 70
    .line 71
    shl-int/lit8 v8, v2, 0x3

    .line 72
    .line 73
    add-int/2addr v8, v7

    .line 74
    aget-object v8, p1, v8

    .line 75
    .line 76
    check-cast v8, Ld4/r;

    .line 77
    .line 78
    iget-object v8, v8, Ld4/r;->a:Ld4/q;

    .line 79
    .line 80
    iget-object v8, v8, Ld4/q;->d:Ld4/l;

    .line 81
    .line 82
    iget-object v8, v8, Ld4/l;->d:Landroidx/collection/q0;

    .line 83
    .line 84
    sget-object v9, Ld4/v;->C:Ld4/z;

    .line 85
    .line 86
    invoke-virtual {v8, v9}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v9

    .line 90
    const/4 v10, 0x0

    .line 91
    if-nez v9, :cond_0

    .line 92
    .line 93
    move-object v9, v10

    .line 94
    :cond_0
    if-eqz v9, :cond_2

    .line 95
    .line 96
    sget-object v9, Ld4/k;->m:Ld4/z;

    .line 97
    .line 98
    invoke-virtual {v8, v9}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v8

    .line 102
    if-nez v8, :cond_1

    .line 103
    .line 104
    goto :goto_2

    .line 105
    :cond_1
    move-object v10, v8

    .line 106
    :goto_2
    check-cast v10, Ld4/a;

    .line 107
    .line 108
    if-eqz v10, :cond_2

    .line 109
    .line 110
    iget-object v8, v10, Ld4/a;->b:Llx0/e;

    .line 111
    .line 112
    check-cast v8, Lay0/a;

    .line 113
    .line 114
    if-eqz v8, :cond_2

    .line 115
    .line 116
    invoke-interface {v8}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v8

    .line 120
    check-cast v8, Ljava/lang/Boolean;

    .line 121
    .line 122
    :cond_2
    shr-long/2addr v3, v6

    .line 123
    add-int/lit8 v7, v7, 0x1

    .line 124
    .line 125
    goto :goto_1

    .line 126
    :cond_3
    if-ne v5, v6, :cond_5

    .line 127
    .line 128
    :cond_4
    if-eq v2, v0, :cond_5

    .line 129
    .line 130
    add-int/lit8 v2, v2, 0x1

    .line 131
    .line 132
    goto :goto_0

    .line 133
    :cond_5
    const/4 p0, 0x1

    .line 134
    return p0
.end method

.method public final onHideTranslation(Landroid/view/View;)Z
    .locals 12

    .line 1
    const-string p0, "null cannot be cast to non-null type androidx.compose.ui.platform.AndroidComposeView"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Lw3/t;

    .line 7
    .line 8
    invoke-virtual {p1}, Lw3/t;->getContentCaptureManager$ui_release()Lz2/e;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    sget-object p1, Lz2/b;->d:Lz2/b;

    .line 16
    .line 17
    iput-object p1, p0, Lz2/e;->i:Lz2/b;

    .line 18
    .line 19
    invoke-virtual {p0}, Lz2/e;->d()Landroidx/collection/p;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    iget-object p1, p0, Landroidx/collection/p;->c:[Ljava/lang/Object;

    .line 24
    .line 25
    iget-object p0, p0, Landroidx/collection/p;->a:[J

    .line 26
    .line 27
    array-length v0, p0

    .line 28
    add-int/lit8 v0, v0, -0x2

    .line 29
    .line 30
    if-ltz v0, :cond_5

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    move v2, v1

    .line 34
    :goto_0
    aget-wide v3, p0, v2

    .line 35
    .line 36
    not-long v5, v3

    .line 37
    const/4 v7, 0x7

    .line 38
    shl-long/2addr v5, v7

    .line 39
    and-long/2addr v5, v3

    .line 40
    const-wide v7, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 41
    .line 42
    .line 43
    .line 44
    .line 45
    and-long/2addr v5, v7

    .line 46
    cmp-long v5, v5, v7

    .line 47
    .line 48
    if-eqz v5, :cond_4

    .line 49
    .line 50
    sub-int v5, v2, v0

    .line 51
    .line 52
    not-int v5, v5

    .line 53
    ushr-int/lit8 v5, v5, 0x1f

    .line 54
    .line 55
    const/16 v6, 0x8

    .line 56
    .line 57
    rsub-int/lit8 v5, v5, 0x8

    .line 58
    .line 59
    move v7, v1

    .line 60
    :goto_1
    if-ge v7, v5, :cond_3

    .line 61
    .line 62
    const-wide/16 v8, 0xff

    .line 63
    .line 64
    and-long/2addr v8, v3

    .line 65
    const-wide/16 v10, 0x80

    .line 66
    .line 67
    cmp-long v8, v8, v10

    .line 68
    .line 69
    if-gez v8, :cond_2

    .line 70
    .line 71
    shl-int/lit8 v8, v2, 0x3

    .line 72
    .line 73
    add-int/2addr v8, v7

    .line 74
    aget-object v8, p1, v8

    .line 75
    .line 76
    check-cast v8, Ld4/r;

    .line 77
    .line 78
    iget-object v8, v8, Ld4/r;->a:Ld4/q;

    .line 79
    .line 80
    iget-object v8, v8, Ld4/q;->d:Ld4/l;

    .line 81
    .line 82
    iget-object v8, v8, Ld4/l;->d:Landroidx/collection/q0;

    .line 83
    .line 84
    sget-object v9, Ld4/v;->C:Ld4/z;

    .line 85
    .line 86
    invoke-virtual {v8, v9}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v9

    .line 90
    const/4 v10, 0x0

    .line 91
    if-nez v9, :cond_0

    .line 92
    .line 93
    move-object v9, v10

    .line 94
    :cond_0
    sget-object v11, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 95
    .line 96
    invoke-static {v9, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v9

    .line 100
    if-eqz v9, :cond_2

    .line 101
    .line 102
    sget-object v9, Ld4/k;->l:Ld4/z;

    .line 103
    .line 104
    invoke-virtual {v8, v9}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v8

    .line 108
    if-nez v8, :cond_1

    .line 109
    .line 110
    goto :goto_2

    .line 111
    :cond_1
    move-object v10, v8

    .line 112
    :goto_2
    check-cast v10, Ld4/a;

    .line 113
    .line 114
    if-eqz v10, :cond_2

    .line 115
    .line 116
    iget-object v8, v10, Ld4/a;->b:Llx0/e;

    .line 117
    .line 118
    check-cast v8, Lay0/k;

    .line 119
    .line 120
    if-eqz v8, :cond_2

    .line 121
    .line 122
    sget-object v9, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 123
    .line 124
    invoke-interface {v8, v9}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v8

    .line 128
    check-cast v8, Ljava/lang/Boolean;

    .line 129
    .line 130
    :cond_2
    shr-long/2addr v3, v6

    .line 131
    add-int/lit8 v7, v7, 0x1

    .line 132
    .line 133
    goto :goto_1

    .line 134
    :cond_3
    if-ne v5, v6, :cond_5

    .line 135
    .line 136
    :cond_4
    if-eq v2, v0, :cond_5

    .line 137
    .line 138
    add-int/lit8 v2, v2, 0x1

    .line 139
    .line 140
    goto :goto_0

    .line 141
    :cond_5
    const/4 p0, 0x1

    .line 142
    return p0
.end method

.method public final onShowTranslation(Landroid/view/View;)Z
    .locals 12

    .line 1
    const-string p0, "null cannot be cast to non-null type androidx.compose.ui.platform.AndroidComposeView"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Lw3/t;

    .line 7
    .line 8
    invoke-virtual {p1}, Lw3/t;->getContentCaptureManager$ui_release()Lz2/e;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    sget-object p1, Lz2/b;->e:Lz2/b;

    .line 16
    .line 17
    iput-object p1, p0, Lz2/e;->i:Lz2/b;

    .line 18
    .line 19
    invoke-virtual {p0}, Lz2/e;->d()Landroidx/collection/p;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    iget-object p1, p0, Landroidx/collection/p;->c:[Ljava/lang/Object;

    .line 24
    .line 25
    iget-object p0, p0, Landroidx/collection/p;->a:[J

    .line 26
    .line 27
    array-length v0, p0

    .line 28
    add-int/lit8 v0, v0, -0x2

    .line 29
    .line 30
    if-ltz v0, :cond_5

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    move v2, v1

    .line 34
    :goto_0
    aget-wide v3, p0, v2

    .line 35
    .line 36
    not-long v5, v3

    .line 37
    const/4 v7, 0x7

    .line 38
    shl-long/2addr v5, v7

    .line 39
    and-long/2addr v5, v3

    .line 40
    const-wide v7, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 41
    .line 42
    .line 43
    .line 44
    .line 45
    and-long/2addr v5, v7

    .line 46
    cmp-long v5, v5, v7

    .line 47
    .line 48
    if-eqz v5, :cond_4

    .line 49
    .line 50
    sub-int v5, v2, v0

    .line 51
    .line 52
    not-int v5, v5

    .line 53
    ushr-int/lit8 v5, v5, 0x1f

    .line 54
    .line 55
    const/16 v6, 0x8

    .line 56
    .line 57
    rsub-int/lit8 v5, v5, 0x8

    .line 58
    .line 59
    move v7, v1

    .line 60
    :goto_1
    if-ge v7, v5, :cond_3

    .line 61
    .line 62
    const-wide/16 v8, 0xff

    .line 63
    .line 64
    and-long/2addr v8, v3

    .line 65
    const-wide/16 v10, 0x80

    .line 66
    .line 67
    cmp-long v8, v8, v10

    .line 68
    .line 69
    if-gez v8, :cond_2

    .line 70
    .line 71
    shl-int/lit8 v8, v2, 0x3

    .line 72
    .line 73
    add-int/2addr v8, v7

    .line 74
    aget-object v8, p1, v8

    .line 75
    .line 76
    check-cast v8, Ld4/r;

    .line 77
    .line 78
    iget-object v8, v8, Ld4/r;->a:Ld4/q;

    .line 79
    .line 80
    iget-object v8, v8, Ld4/q;->d:Ld4/l;

    .line 81
    .line 82
    iget-object v8, v8, Ld4/l;->d:Landroidx/collection/q0;

    .line 83
    .line 84
    sget-object v9, Ld4/v;->C:Ld4/z;

    .line 85
    .line 86
    invoke-virtual {v8, v9}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v9

    .line 90
    const/4 v10, 0x0

    .line 91
    if-nez v9, :cond_0

    .line 92
    .line 93
    move-object v9, v10

    .line 94
    :cond_0
    sget-object v11, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 95
    .line 96
    invoke-static {v9, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v9

    .line 100
    if-eqz v9, :cond_2

    .line 101
    .line 102
    sget-object v9, Ld4/k;->l:Ld4/z;

    .line 103
    .line 104
    invoke-virtual {v8, v9}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v8

    .line 108
    if-nez v8, :cond_1

    .line 109
    .line 110
    goto :goto_2

    .line 111
    :cond_1
    move-object v10, v8

    .line 112
    :goto_2
    check-cast v10, Ld4/a;

    .line 113
    .line 114
    if-eqz v10, :cond_2

    .line 115
    .line 116
    iget-object v8, v10, Ld4/a;->b:Llx0/e;

    .line 117
    .line 118
    check-cast v8, Lay0/k;

    .line 119
    .line 120
    if-eqz v8, :cond_2

    .line 121
    .line 122
    sget-object v9, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 123
    .line 124
    invoke-interface {v8, v9}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v8

    .line 128
    check-cast v8, Ljava/lang/Boolean;

    .line 129
    .line 130
    :cond_2
    shr-long/2addr v3, v6

    .line 131
    add-int/lit8 v7, v7, 0x1

    .line 132
    .line 133
    goto :goto_1

    .line 134
    :cond_3
    if-ne v5, v6, :cond_5

    .line 135
    .line 136
    :cond_4
    if-eq v2, v0, :cond_5

    .line 137
    .line 138
    add-int/lit8 v2, v2, 0x1

    .line 139
    .line 140
    goto :goto_0

    .line 141
    :cond_5
    const/4 p0, 0x1

    .line 142
    return p0
.end method
