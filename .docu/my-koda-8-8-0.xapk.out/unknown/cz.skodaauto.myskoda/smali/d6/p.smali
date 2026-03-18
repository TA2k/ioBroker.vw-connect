.class public final Ld6/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Landroid/view/ViewParent;

.field public b:Landroid/view/ViewParent;

.field public final c:Landroid/view/ViewGroup;

.field public d:Z

.field public e:[I


# direct methods
.method public constructor <init>(Landroid/view/ViewGroup;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ld6/p;->c:Landroid/view/ViewGroup;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(FFZ)Z
    .locals 2

    .line 1
    iget-boolean v0, p0, Ld6/p;->d:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Ld6/p;->e(I)Landroid/view/ViewParent;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, Ld6/p;->c:Landroid/view/ViewGroup;

    .line 13
    .line 14
    :try_start_0
    invoke-interface {v0, p0, p1, p2, p3}, Landroid/view/ViewParent;->onNestedFling(Landroid/view/View;FFZ)Z

    .line 15
    .line 16
    .line 17
    move-result p0
    :try_end_0
    .catch Ljava/lang/AbstractMethodError; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    return p0

    .line 19
    :catch_0
    move-exception p0

    .line 20
    new-instance p1, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    const-string p2, "ViewParent "

    .line 23
    .line 24
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string p2, " does not implement interface method onNestedFling"

    .line 31
    .line 32
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    const-string p2, "ViewParentCompat"

    .line 40
    .line 41
    invoke-static {p2, p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 42
    .line 43
    .line 44
    :cond_0
    return v1
.end method

.method public final b(FF)Z
    .locals 2

    .line 1
    iget-boolean v0, p0, Ld6/p;->d:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Ld6/p;->e(I)Landroid/view/ViewParent;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, Ld6/p;->c:Landroid/view/ViewGroup;

    .line 13
    .line 14
    :try_start_0
    invoke-interface {v0, p0, p1, p2}, Landroid/view/ViewParent;->onNestedPreFling(Landroid/view/View;FF)Z

    .line 15
    .line 16
    .line 17
    move-result p0
    :try_end_0
    .catch Ljava/lang/AbstractMethodError; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    return p0

    .line 19
    :catch_0
    move-exception p0

    .line 20
    new-instance p1, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    const-string p2, "ViewParent "

    .line 23
    .line 24
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string p2, " does not implement interface method onNestedPreFling"

    .line 31
    .line 32
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    const-string p2, "ViewParentCompat"

    .line 40
    .line 41
    invoke-static {p2, p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 42
    .line 43
    .line 44
    :cond_0
    return v1
.end method

.method public final c(III[I[I)Z
    .locals 11

    .line 1
    move-object/from16 v6, p5

    .line 2
    .line 3
    iget-boolean v1, p0, Ld6/p;->d:Z

    .line 4
    .line 5
    const/4 v7, 0x0

    .line 6
    if-eqz v1, :cond_a

    .line 7
    .line 8
    invoke-virtual {p0, p3}, Ld6/p;->e(I)Landroid/view/ViewParent;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    if-nez v1, :cond_0

    .line 13
    .line 14
    goto/16 :goto_4

    .line 15
    .line 16
    :cond_0
    const/4 v8, 0x1

    .line 17
    if-nez p1, :cond_2

    .line 18
    .line 19
    if-eqz p2, :cond_1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_1
    if-eqz v6, :cond_a

    .line 23
    .line 24
    aput v7, v6, v7

    .line 25
    .line 26
    aput v7, v6, v8

    .line 27
    .line 28
    return v7

    .line 29
    :cond_2
    :goto_0
    iget-object v2, p0, Ld6/p;->c:Landroid/view/ViewGroup;

    .line 30
    .line 31
    if-eqz v6, :cond_3

    .line 32
    .line 33
    invoke-virtual {v2, v6}, Landroid/view/View;->getLocationInWindow([I)V

    .line 34
    .line 35
    .line 36
    aget v3, v6, v7

    .line 37
    .line 38
    aget v4, v6, v8

    .line 39
    .line 40
    move v9, v3

    .line 41
    move v10, v4

    .line 42
    goto :goto_1

    .line 43
    :cond_3
    move v9, v7

    .line 44
    move v10, v9

    .line 45
    :goto_1
    if-nez p4, :cond_5

    .line 46
    .line 47
    iget-object v3, p0, Ld6/p;->e:[I

    .line 48
    .line 49
    if-nez v3, :cond_4

    .line 50
    .line 51
    const/4 v3, 0x2

    .line 52
    new-array v3, v3, [I

    .line 53
    .line 54
    iput-object v3, p0, Ld6/p;->e:[I

    .line 55
    .line 56
    :cond_4
    iget-object v0, p0, Ld6/p;->e:[I

    .line 57
    .line 58
    move-object v4, v0

    .line 59
    goto :goto_2

    .line 60
    :cond_5
    move-object v4, p4

    .line 61
    :goto_2
    aput v7, v4, v7

    .line 62
    .line 63
    aput v7, v4, v8

    .line 64
    .line 65
    instance-of v0, v1, Ld6/q;

    .line 66
    .line 67
    if-eqz v0, :cond_6

    .line 68
    .line 69
    move-object v0, v1

    .line 70
    check-cast v0, Ld6/q;

    .line 71
    .line 72
    move v3, p2

    .line 73
    move v5, p3

    .line 74
    move-object v1, v2

    .line 75
    move v2, p1

    .line 76
    invoke-interface/range {v0 .. v5}, Ld6/q;->d(Landroid/view/View;II[II)V

    .line 77
    .line 78
    .line 79
    move-object v2, v1

    .line 80
    goto :goto_3

    .line 81
    :cond_6
    if-nez p3, :cond_7

    .line 82
    .line 83
    :try_start_0
    invoke-interface {v1, v2, p1, p2, v4}, Landroid/view/ViewParent;->onNestedPreScroll(Landroid/view/View;II[I)V
    :try_end_0
    .catch Ljava/lang/AbstractMethodError; {:try_start_0 .. :try_end_0} :catch_0

    .line 84
    .line 85
    .line 86
    goto :goto_3

    .line 87
    :catch_0
    move-exception v0

    .line 88
    new-instance v3, Ljava/lang/StringBuilder;

    .line 89
    .line 90
    const-string v5, "ViewParent "

    .line 91
    .line 92
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    const-string v1, " does not implement interface method onNestedPreScroll"

    .line 99
    .line 100
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    const-string v3, "ViewParentCompat"

    .line 108
    .line 109
    invoke-static {v3, v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 110
    .line 111
    .line 112
    :cond_7
    :goto_3
    if-eqz v6, :cond_8

    .line 113
    .line 114
    invoke-virtual {v2, v6}, Landroid/view/View;->getLocationInWindow([I)V

    .line 115
    .line 116
    .line 117
    aget v0, v6, v7

    .line 118
    .line 119
    sub-int/2addr v0, v9

    .line 120
    aput v0, v6, v7

    .line 121
    .line 122
    aget v0, v6, v8

    .line 123
    .line 124
    sub-int/2addr v0, v10

    .line 125
    aput v0, v6, v8

    .line 126
    .line 127
    :cond_8
    aget v0, v4, v7

    .line 128
    .line 129
    if-nez v0, :cond_9

    .line 130
    .line 131
    aget v0, v4, v8

    .line 132
    .line 133
    if-eqz v0, :cond_a

    .line 134
    .line 135
    :cond_9
    move v7, v8

    .line 136
    :cond_a
    :goto_4
    return v7
.end method

.method public final d(IIII[II[I)Z
    .locals 14

    .line 1
    move-object/from16 v1, p5

    .line 2
    .line 3
    move/from16 v8, p6

    .line 4
    .line 5
    iget-boolean v0, p0, Ld6/p;->d:Z

    .line 6
    .line 7
    const/4 v10, 0x0

    .line 8
    if-eqz v0, :cond_a

    .line 9
    .line 10
    invoke-virtual {p0, v8}, Ld6/p;->e(I)Landroid/view/ViewParent;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    if-nez v2, :cond_0

    .line 15
    .line 16
    goto/16 :goto_4

    .line 17
    .line 18
    :cond_0
    const/4 v11, 0x1

    .line 19
    if-nez p1, :cond_2

    .line 20
    .line 21
    if-nez p2, :cond_2

    .line 22
    .line 23
    if-nez p3, :cond_2

    .line 24
    .line 25
    if-eqz p4, :cond_1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    if-eqz v1, :cond_a

    .line 29
    .line 30
    aput v10, v1, v10

    .line 31
    .line 32
    aput v10, v1, v11

    .line 33
    .line 34
    return v10

    .line 35
    :cond_2
    :goto_0
    iget-object v3, p0, Ld6/p;->c:Landroid/view/ViewGroup;

    .line 36
    .line 37
    if-eqz v1, :cond_3

    .line 38
    .line 39
    invoke-virtual {v3, v1}, Landroid/view/View;->getLocationInWindow([I)V

    .line 40
    .line 41
    .line 42
    aget v0, v1, v10

    .line 43
    .line 44
    aget v4, v1, v11

    .line 45
    .line 46
    move v12, v0

    .line 47
    move v13, v4

    .line 48
    goto :goto_1

    .line 49
    :cond_3
    move v12, v10

    .line 50
    move v13, v12

    .line 51
    :goto_1
    if-nez p7, :cond_5

    .line 52
    .line 53
    iget-object v0, p0, Ld6/p;->e:[I

    .line 54
    .line 55
    if-nez v0, :cond_4

    .line 56
    .line 57
    const/4 v0, 0x2

    .line 58
    new-array v0, v0, [I

    .line 59
    .line 60
    iput-object v0, p0, Ld6/p;->e:[I

    .line 61
    .line 62
    :cond_4
    iget-object p0, p0, Ld6/p;->e:[I

    .line 63
    .line 64
    aput v10, p0, v10

    .line 65
    .line 66
    aput v10, p0, v11

    .line 67
    .line 68
    move-object v9, p0

    .line 69
    goto :goto_2

    .line 70
    :cond_5
    move-object/from16 v9, p7

    .line 71
    .line 72
    :goto_2
    instance-of p0, v2, Ld6/r;

    .line 73
    .line 74
    if-eqz p0, :cond_6

    .line 75
    .line 76
    check-cast v2, Ld6/r;

    .line 77
    .line 78
    move v4, p1

    .line 79
    move/from16 v5, p2

    .line 80
    .line 81
    move/from16 v6, p3

    .line 82
    .line 83
    move/from16 v7, p4

    .line 84
    .line 85
    invoke-interface/range {v2 .. v9}, Ld6/r;->g(Landroid/view/View;IIIII[I)V

    .line 86
    .line 87
    .line 88
    goto :goto_3

    .line 89
    :cond_6
    aget p0, v9, v10

    .line 90
    .line 91
    add-int p0, p0, p3

    .line 92
    .line 93
    aput p0, v9, v10

    .line 94
    .line 95
    aget p0, v9, v11

    .line 96
    .line 97
    add-int p0, p0, p4

    .line 98
    .line 99
    aput p0, v9, v11

    .line 100
    .line 101
    instance-of p0, v2, Ld6/q;

    .line 102
    .line 103
    if-eqz p0, :cond_7

    .line 104
    .line 105
    check-cast v2, Ld6/q;

    .line 106
    .line 107
    move v4, p1

    .line 108
    move/from16 v5, p2

    .line 109
    .line 110
    move/from16 v6, p3

    .line 111
    .line 112
    move/from16 v7, p4

    .line 113
    .line 114
    move/from16 v8, p6

    .line 115
    .line 116
    invoke-interface/range {v2 .. v8}, Ld6/q;->h(Landroid/view/View;IIIII)V

    .line 117
    .line 118
    .line 119
    goto :goto_3

    .line 120
    :cond_7
    if-nez p6, :cond_8

    .line 121
    .line 122
    move v4, p1

    .line 123
    move/from16 v5, p2

    .line 124
    .line 125
    move/from16 v6, p3

    .line 126
    .line 127
    move/from16 v7, p4

    .line 128
    .line 129
    :try_start_0
    invoke-interface/range {v2 .. v7}, Landroid/view/ViewParent;->onNestedScroll(Landroid/view/View;IIII)V
    :try_end_0
    .catch Ljava/lang/AbstractMethodError; {:try_start_0 .. :try_end_0} :catch_0

    .line 130
    .line 131
    .line 132
    goto :goto_3

    .line 133
    :catch_0
    move-exception v0

    .line 134
    move-object p0, v0

    .line 135
    new-instance p1, Ljava/lang/StringBuilder;

    .line 136
    .line 137
    const-string v0, "ViewParent "

    .line 138
    .line 139
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    const-string v0, " does not implement interface method onNestedScroll"

    .line 146
    .line 147
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 148
    .line 149
    .line 150
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    const-string v0, "ViewParentCompat"

    .line 155
    .line 156
    invoke-static {v0, p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 157
    .line 158
    .line 159
    :cond_8
    :goto_3
    if-eqz v1, :cond_9

    .line 160
    .line 161
    invoke-virtual {v3, v1}, Landroid/view/View;->getLocationInWindow([I)V

    .line 162
    .line 163
    .line 164
    aget p0, v1, v10

    .line 165
    .line 166
    sub-int/2addr p0, v12

    .line 167
    aput p0, v1, v10

    .line 168
    .line 169
    aget p0, v1, v11

    .line 170
    .line 171
    sub-int/2addr p0, v13

    .line 172
    aput p0, v1, v11

    .line 173
    .line 174
    :cond_9
    return v11

    .line 175
    :cond_a
    :goto_4
    return v10
.end method

.method public final e(I)Landroid/view/ViewParent;
    .locals 1

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-eq p1, v0, :cond_0

    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    return-object p0

    .line 8
    :cond_0
    iget-object p0, p0, Ld6/p;->b:Landroid/view/ViewParent;

    .line 9
    .line 10
    return-object p0

    .line 11
    :cond_1
    iget-object p0, p0, Ld6/p;->a:Landroid/view/ViewParent;

    .line 12
    .line 13
    return-object p0
.end method

.method public final f(I)Z
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Ld6/p;->e(I)Landroid/view/ViewParent;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public final g(II)Z
    .locals 11

    .line 1
    invoke-virtual {p0, p2}, Ld6/p;->f(I)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    goto/16 :goto_3

    .line 9
    .line 10
    :cond_0
    iget-boolean v0, p0, Ld6/p;->d:Z

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    if-eqz v0, :cond_9

    .line 14
    .line 15
    iget-object v0, p0, Ld6/p;->c:Landroid/view/ViewGroup;

    .line 16
    .line 17
    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    move-object v4, v0

    .line 22
    :goto_0
    if-eqz v3, :cond_9

    .line 23
    .line 24
    instance-of v5, v3, Ld6/q;

    .line 25
    .line 26
    const-string v6, "ViewParent "

    .line 27
    .line 28
    const-string v7, "ViewParentCompat"

    .line 29
    .line 30
    if-eqz v5, :cond_1

    .line 31
    .line 32
    move-object v8, v3

    .line 33
    check-cast v8, Ld6/q;

    .line 34
    .line 35
    invoke-interface {v8, v4, v0, p1, p2}, Ld6/q;->i(Landroid/view/View;Landroid/view/View;II)Z

    .line 36
    .line 37
    .line 38
    move-result v8

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    if-nez p2, :cond_2

    .line 41
    .line 42
    :try_start_0
    invoke-interface {v3, v4, v0, p1}, Landroid/view/ViewParent;->onStartNestedScroll(Landroid/view/View;Landroid/view/View;I)Z

    .line 43
    .line 44
    .line 45
    move-result v8
    :try_end_0
    .catch Ljava/lang/AbstractMethodError; {:try_start_0 .. :try_end_0} :catch_0

    .line 46
    goto :goto_1

    .line 47
    :catch_0
    move-exception v8

    .line 48
    new-instance v9, Ljava/lang/StringBuilder;

    .line 49
    .line 50
    invoke-direct {v9, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v9, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    const-string v10, " does not implement interface method onStartNestedScroll"

    .line 57
    .line 58
    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v9

    .line 65
    invoke-static {v7, v9, v8}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 66
    .line 67
    .line 68
    :cond_2
    move v8, v2

    .line 69
    :goto_1
    if-eqz v8, :cond_7

    .line 70
    .line 71
    if-eqz p2, :cond_4

    .line 72
    .line 73
    if-eq p2, v1, :cond_3

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_3
    iput-object v3, p0, Ld6/p;->b:Landroid/view/ViewParent;

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_4
    iput-object v3, p0, Ld6/p;->a:Landroid/view/ViewParent;

    .line 80
    .line 81
    :goto_2
    if-eqz v5, :cond_5

    .line 82
    .line 83
    check-cast v3, Ld6/q;

    .line 84
    .line 85
    invoke-interface {v3, v4, v0, p1, p2}, Ld6/q;->b(Landroid/view/View;Landroid/view/View;II)V

    .line 86
    .line 87
    .line 88
    goto :goto_3

    .line 89
    :cond_5
    if-nez p2, :cond_6

    .line 90
    .line 91
    :try_start_1
    invoke-interface {v3, v4, v0, p1}, Landroid/view/ViewParent;->onNestedScrollAccepted(Landroid/view/View;Landroid/view/View;I)V
    :try_end_1
    .catch Ljava/lang/AbstractMethodError; {:try_start_1 .. :try_end_1} :catch_1

    .line 92
    .line 93
    .line 94
    goto :goto_3

    .line 95
    :catch_1
    move-exception p0

    .line 96
    new-instance p1, Ljava/lang/StringBuilder;

    .line 97
    .line 98
    invoke-direct {p1, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {p1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    const-string p2, " does not implement interface method onNestedScrollAccepted"

    .line 105
    .line 106
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    invoke-static {v7, p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 114
    .line 115
    .line 116
    :cond_6
    :goto_3
    return v1

    .line 117
    :cond_7
    instance-of v5, v3, Landroid/view/View;

    .line 118
    .line 119
    if-eqz v5, :cond_8

    .line 120
    .line 121
    move-object v4, v3

    .line 122
    check-cast v4, Landroid/view/View;

    .line 123
    .line 124
    :cond_8
    invoke-interface {v3}, Landroid/view/ViewParent;->getParent()Landroid/view/ViewParent;

    .line 125
    .line 126
    .line 127
    move-result-object v3

    .line 128
    goto :goto_0

    .line 129
    :cond_9
    return v2
.end method

.method public final h(I)V
    .locals 4

    .line 1
    invoke-virtual {p0, p1}, Ld6/p;->e(I)Landroid/view/ViewParent;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_4

    .line 6
    .line 7
    instance-of v1, v0, Ld6/q;

    .line 8
    .line 9
    iget-object v2, p0, Ld6/p;->c:Landroid/view/ViewGroup;

    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    check-cast v0, Ld6/q;

    .line 14
    .line 15
    invoke-interface {v0, v2, p1}, Ld6/q;->c(Landroid/view/View;I)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    if-nez p1, :cond_1

    .line 20
    .line 21
    :try_start_0
    invoke-interface {v0, v2}, Landroid/view/ViewParent;->onStopNestedScroll(Landroid/view/View;)V
    :try_end_0
    .catch Ljava/lang/AbstractMethodError; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :catch_0
    move-exception v1

    .line 26
    new-instance v2, Ljava/lang/StringBuilder;

    .line 27
    .line 28
    const-string v3, "ViewParent "

    .line 29
    .line 30
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    const-string v0, " does not implement interface method onStopNestedScroll"

    .line 37
    .line 38
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    const-string v2, "ViewParentCompat"

    .line 46
    .line 47
    invoke-static {v2, v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 48
    .line 49
    .line 50
    :cond_1
    :goto_0
    const/4 v0, 0x0

    .line 51
    if-eqz p1, :cond_3

    .line 52
    .line 53
    const/4 v1, 0x1

    .line 54
    if-eq p1, v1, :cond_2

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_2
    iput-object v0, p0, Ld6/p;->b:Landroid/view/ViewParent;

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_3
    iput-object v0, p0, Ld6/p;->a:Landroid/view/ViewParent;

    .line 61
    .line 62
    :cond_4
    :goto_1
    return-void
.end method
