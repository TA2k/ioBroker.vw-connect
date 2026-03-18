.class public final Lbb/h;
.super Lbb/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final I:[Ljava/lang/String;


# instance fields
.field public final H:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-string v0, "android:visibility:visibility"

    .line 2
    .line 3
    const-string v1, "android:visibility:parent"

    .line 4
    .line 5
    filled-new-array {v0, v1}, [Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lbb/h;->I:[Ljava/lang/String;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 3
    invoke-direct {p0}, Lbb/x;-><init>()V

    const/4 v0, 0x3

    .line 4
    iput v0, p0, Lbb/h;->H:I

    return-void
.end method

.method public constructor <init>(I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lbb/h;-><init>()V

    .line 2
    iput p1, p0, Lbb/h;->H:I

    return-void
.end method

.method public static O(Lbb/f0;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lbb/f0;->b:Landroid/view/View;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/view/View;->getVisibility()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    iget-object p0, p0, Lbb/f0;->a:Ljava/util/HashMap;

    .line 8
    .line 9
    const-string v2, "android:visibility:visibility"

    .line 10
    .line 11
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-virtual {p0, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    const-string v1, "android:visibility:parent"

    .line 19
    .line 20
    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    invoke-virtual {p0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    const/4 v1, 0x2

    .line 28
    new-array v1, v1, [I

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Landroid/view/View;->getLocationOnScreen([I)V

    .line 31
    .line 32
    .line 33
    const-string v0, "android:visibility:screenLocation"

    .line 34
    .line 35
    invoke-virtual {p0, v0, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public static Q(Lbb/f0;F)F
    .locals 1

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    iget-object p0, p0, Lbb/f0;->a:Ljava/util/HashMap;

    .line 4
    .line 5
    const-string v0, "android:fade:transitionAlpha"

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Ljava/lang/Float;

    .line 12
    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Float;->floatValue()F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :cond_0
    return p1
.end method

.method public static R(Lbb/f0;Lbb/f0;)La8/p1;
    .locals 8

    .line 1
    new-instance v0, La8/p1;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    iput-boolean v1, v0, La8/p1;->a:Z

    .line 8
    .line 9
    iput-boolean v1, v0, La8/p1;->b:Z

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, -0x1

    .line 13
    const-string v4, "android:visibility:parent"

    .line 14
    .line 15
    const-string v5, "android:visibility:visibility"

    .line 16
    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    iget-object v6, p0, Lbb/f0;->a:Ljava/util/HashMap;

    .line 20
    .line 21
    invoke-virtual {v6, v5}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v7

    .line 25
    if-eqz v7, :cond_0

    .line 26
    .line 27
    invoke-virtual {v6, v5}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v7

    .line 31
    check-cast v7, Ljava/lang/Integer;

    .line 32
    .line 33
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 34
    .line 35
    .line 36
    move-result v7

    .line 37
    iput v7, v0, La8/p1;->c:I

    .line 38
    .line 39
    invoke-virtual {v6, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v6

    .line 43
    check-cast v6, Landroid/view/ViewGroup;

    .line 44
    .line 45
    iput-object v6, v0, La8/p1;->e:Ljava/lang/Object;

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    iput v3, v0, La8/p1;->c:I

    .line 49
    .line 50
    iput-object v2, v0, La8/p1;->e:Ljava/lang/Object;

    .line 51
    .line 52
    :goto_0
    if-eqz p1, :cond_1

    .line 53
    .line 54
    iget-object v6, p1, Lbb/f0;->a:Ljava/util/HashMap;

    .line 55
    .line 56
    invoke-virtual {v6, v5}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v7

    .line 60
    if-eqz v7, :cond_1

    .line 61
    .line 62
    invoke-virtual {v6, v5}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    check-cast v2, Ljava/lang/Integer;

    .line 67
    .line 68
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    iput v2, v0, La8/p1;->d:I

    .line 73
    .line 74
    invoke-virtual {v6, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    check-cast v2, Landroid/view/ViewGroup;

    .line 79
    .line 80
    iput-object v2, v0, La8/p1;->f:Ljava/lang/Object;

    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_1
    iput v3, v0, La8/p1;->d:I

    .line 84
    .line 85
    iput-object v2, v0, La8/p1;->f:Ljava/lang/Object;

    .line 86
    .line 87
    :goto_1
    const/4 v2, 0x1

    .line 88
    if-eqz p0, :cond_6

    .line 89
    .line 90
    if-eqz p1, :cond_6

    .line 91
    .line 92
    iget p0, v0, La8/p1;->c:I

    .line 93
    .line 94
    iget p1, v0, La8/p1;->d:I

    .line 95
    .line 96
    if-ne p0, p1, :cond_2

    .line 97
    .line 98
    iget-object v3, v0, La8/p1;->e:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v3, Landroid/view/ViewGroup;

    .line 101
    .line 102
    iget-object v4, v0, La8/p1;->f:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast v4, Landroid/view/ViewGroup;

    .line 105
    .line 106
    if-ne v3, v4, :cond_2

    .line 107
    .line 108
    goto :goto_2

    .line 109
    :cond_2
    if-eq p0, p1, :cond_4

    .line 110
    .line 111
    if-nez p0, :cond_3

    .line 112
    .line 113
    iput-boolean v1, v0, La8/p1;->b:Z

    .line 114
    .line 115
    iput-boolean v2, v0, La8/p1;->a:Z

    .line 116
    .line 117
    return-object v0

    .line 118
    :cond_3
    if-nez p1, :cond_8

    .line 119
    .line 120
    iput-boolean v2, v0, La8/p1;->b:Z

    .line 121
    .line 122
    iput-boolean v2, v0, La8/p1;->a:Z

    .line 123
    .line 124
    return-object v0

    .line 125
    :cond_4
    iget-object p0, v0, La8/p1;->f:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast p0, Landroid/view/ViewGroup;

    .line 128
    .line 129
    if-nez p0, :cond_5

    .line 130
    .line 131
    iput-boolean v1, v0, La8/p1;->b:Z

    .line 132
    .line 133
    iput-boolean v2, v0, La8/p1;->a:Z

    .line 134
    .line 135
    return-object v0

    .line 136
    :cond_5
    iget-object p0, v0, La8/p1;->e:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast p0, Landroid/view/ViewGroup;

    .line 139
    .line 140
    if-nez p0, :cond_8

    .line 141
    .line 142
    iput-boolean v2, v0, La8/p1;->b:Z

    .line 143
    .line 144
    iput-boolean v2, v0, La8/p1;->a:Z

    .line 145
    .line 146
    return-object v0

    .line 147
    :cond_6
    if-nez p0, :cond_7

    .line 148
    .line 149
    iget p0, v0, La8/p1;->d:I

    .line 150
    .line 151
    if-nez p0, :cond_7

    .line 152
    .line 153
    iput-boolean v2, v0, La8/p1;->b:Z

    .line 154
    .line 155
    iput-boolean v2, v0, La8/p1;->a:Z

    .line 156
    .line 157
    return-object v0

    .line 158
    :cond_7
    if-nez p1, :cond_8

    .line 159
    .line 160
    iget p0, v0, La8/p1;->c:I

    .line 161
    .line 162
    if-nez p0, :cond_8

    .line 163
    .line 164
    iput-boolean v1, v0, La8/p1;->b:Z

    .line 165
    .line 166
    iput-boolean v2, v0, La8/p1;->a:Z

    .line 167
    .line 168
    :cond_8
    :goto_2
    return-object v0
.end method


# virtual methods
.method public final P(Landroid/view/View;FF)Landroid/animation/ObjectAnimator;
    .locals 2

    .line 1
    cmpl-float v0, p2, p3

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return-object p0

    .line 7
    :cond_0
    sget-object v0, Lbb/i0;->a:Lbb/b;

    .line 8
    .line 9
    invoke-virtual {p1, p2}, Landroid/view/View;->setTransitionAlpha(F)V

    .line 10
    .line 11
    .line 12
    sget-object p2, Lbb/i0;->a:Lbb/b;

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    new-array v0, v0, [F

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    aput p3, v0, v1

    .line 19
    .line 20
    invoke-static {p1, p2, v0}, Landroid/animation/ObjectAnimator;->ofFloat(Ljava/lang/Object;Landroid/util/Property;[F)Landroid/animation/ObjectAnimator;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    new-instance p3, Lbb/g;

    .line 25
    .line 26
    invoke-direct {p3, p1}, Lbb/g;-><init>(Landroid/view/View;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p2, p3}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0}, Lbb/x;->p()Lbb/x;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-virtual {p0, p3}, Lbb/x;->a(Lbb/v;)V

    .line 37
    .line 38
    .line 39
    return-object p2
.end method

.method public final d(Lbb/f0;)V
    .locals 0

    .line 1
    invoke-static {p1}, Lbb/h;->O(Lbb/f0;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final h(Lbb/f0;)V
    .locals 1

    .line 1
    invoke-static {p1}, Lbb/h;->O(Lbb/f0;)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p1, Lbb/f0;->b:Landroid/view/View;

    .line 5
    .line 6
    const v0, 0x7f0a02f3

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, v0}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Ljava/lang/Float;

    .line 14
    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0}, Landroid/view/View;->getVisibility()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_0

    .line 22
    .line 23
    sget-object v0, Lbb/i0;->a:Lbb/b;

    .line 24
    .line 25
    invoke-virtual {p0}, Landroid/view/View;->getTransitionAlpha()F

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 p0, 0x0

    .line 35
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    :cond_1
    :goto_0
    iget-object p0, p1, Lbb/f0;->a:Ljava/util/HashMap;

    .line 40
    .line 41
    const-string p1, "android:fade:transitionAlpha"

    .line 42
    .line 43
    invoke-virtual {p0, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public final l(Landroid/view/ViewGroup;Lbb/f0;Lbb/f0;)Landroid/animation/Animator;
    .locals 23

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
    move-object/from16 v3, p3

    .line 8
    .line 9
    invoke-static/range {p2 .. p3}, Lbb/h;->R(Lbb/f0;Lbb/f0;)La8/p1;

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    iget-boolean v5, v4, La8/p1;->a:Z

    .line 14
    .line 15
    if-eqz v5, :cond_0

    .line 16
    .line 17
    iget-object v5, v4, La8/p1;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v5, Landroid/view/ViewGroup;

    .line 20
    .line 21
    if-nez v5, :cond_1

    .line 22
    .line 23
    iget-object v5, v4, La8/p1;->f:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v5, Landroid/view/ViewGroup;

    .line 26
    .line 27
    if-eqz v5, :cond_0

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_0
    :goto_0
    const/16 v16, 0x0

    .line 31
    .line 32
    goto/16 :goto_d

    .line 33
    .line 34
    :cond_1
    :goto_1
    iget-boolean v5, v4, La8/p1;->b:Z

    .line 35
    .line 36
    iget v7, v0, Lbb/h;->H:I

    .line 37
    .line 38
    const/high16 v8, 0x3f800000    # 1.0f

    .line 39
    .line 40
    const/4 v9, 0x0

    .line 41
    const/4 v10, 0x1

    .line 42
    const/4 v11, 0x0

    .line 43
    if-eqz v5, :cond_4

    .line 44
    .line 45
    and-int/lit8 v1, v7, 0x1

    .line 46
    .line 47
    if-ne v1, v10, :cond_0

    .line 48
    .line 49
    if-nez v3, :cond_2

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_2
    iget-object v1, v3, Lbb/f0;->b:Landroid/view/View;

    .line 53
    .line 54
    if-nez v2, :cond_3

    .line 55
    .line 56
    invoke-virtual {v1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    check-cast v3, Landroid/view/View;

    .line 61
    .line 62
    invoke-virtual {v0, v3, v11}, Lbb/x;->o(Landroid/view/View;Z)Lbb/f0;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    invoke-virtual {v0, v3, v11}, Lbb/x;->s(Landroid/view/View;Z)Lbb/f0;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    invoke-static {v4, v3}, Lbb/h;->R(Lbb/f0;Lbb/f0;)La8/p1;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    iget-boolean v3, v3, La8/p1;->a:Z

    .line 75
    .line 76
    if-eqz v3, :cond_3

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_3
    sget-object v3, Lbb/i0;->a:Lbb/b;

    .line 80
    .line 81
    invoke-static {v2, v9}, Lbb/h;->Q(Lbb/f0;F)F

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    invoke-virtual {v0, v1, v2, v8}, Lbb/h;->P(Landroid/view/View;FF)Landroid/animation/ObjectAnimator;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    return-object v0

    .line 90
    :cond_4
    iget v4, v4, La8/p1;->d:I

    .line 91
    .line 92
    const/4 v5, 0x2

    .line 93
    and-int/2addr v7, v5

    .line 94
    if-eq v7, v5, :cond_5

    .line 95
    .line 96
    goto :goto_0

    .line 97
    :cond_5
    if-nez v2, :cond_6

    .line 98
    .line 99
    goto :goto_0

    .line 100
    :cond_6
    iget-object v7, v2, Lbb/f0;->b:Landroid/view/View;

    .line 101
    .line 102
    if-eqz v3, :cond_7

    .line 103
    .line 104
    iget-object v12, v3, Lbb/f0;->b:Landroid/view/View;

    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_7
    const/4 v12, 0x0

    .line 108
    :goto_2
    const v13, 0x7f0a027b

    .line 109
    .line 110
    .line 111
    invoke-virtual {v7, v13}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v14

    .line 115
    check-cast v14, Landroid/view/View;

    .line 116
    .line 117
    if-eqz v14, :cond_8

    .line 118
    .line 119
    move/from16 v22, v4

    .line 120
    .line 121
    move/from16 v18, v10

    .line 122
    .line 123
    move/from16 v17, v11

    .line 124
    .line 125
    const/4 v6, 0x0

    .line 126
    const/16 v16, 0x0

    .line 127
    .line 128
    goto/16 :goto_c

    .line 129
    .line 130
    :cond_8
    if-eqz v12, :cond_c

    .line 131
    .line 132
    invoke-virtual {v12}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 133
    .line 134
    .line 135
    move-result-object v14

    .line 136
    if-nez v14, :cond_9

    .line 137
    .line 138
    goto :goto_5

    .line 139
    :cond_9
    const/4 v14, 0x4

    .line 140
    if-ne v4, v14, :cond_a

    .line 141
    .line 142
    goto :goto_3

    .line 143
    :cond_a
    if-ne v7, v12, :cond_b

    .line 144
    .line 145
    :goto_3
    move v15, v11

    .line 146
    move-object v14, v12

    .line 147
    const/4 v12, 0x0

    .line 148
    goto :goto_6

    .line 149
    :cond_b
    move v15, v10

    .line 150
    const/4 v12, 0x0

    .line 151
    :goto_4
    const/4 v14, 0x0

    .line 152
    goto :goto_6

    .line 153
    :cond_c
    :goto_5
    if-eqz v12, :cond_b

    .line 154
    .line 155
    move v15, v11

    .line 156
    goto :goto_4

    .line 157
    :goto_6
    if-eqz v15, :cond_14

    .line 158
    .line 159
    invoke-virtual {v7}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 160
    .line 161
    .line 162
    move-result-object v15

    .line 163
    if-nez v15, :cond_d

    .line 164
    .line 165
    move/from16 v22, v4

    .line 166
    .line 167
    move/from16 v18, v10

    .line 168
    .line 169
    move v10, v11

    .line 170
    move/from16 v17, v10

    .line 171
    .line 172
    move-object v6, v14

    .line 173
    const/16 v16, 0x0

    .line 174
    .line 175
    move-object v14, v7

    .line 176
    goto/16 :goto_c

    .line 177
    .line 178
    :cond_d
    invoke-virtual {v7}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 179
    .line 180
    .line 181
    move-result-object v15

    .line 182
    instance-of v15, v15, Landroid/view/View;

    .line 183
    .line 184
    if-eqz v15, :cond_14

    .line 185
    .line 186
    invoke-virtual {v7}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 187
    .line 188
    .line 189
    move-result-object v15

    .line 190
    check-cast v15, Landroid/view/View;

    .line 191
    .line 192
    const/16 v16, 0x0

    .line 193
    .line 194
    invoke-virtual {v0, v15, v10}, Lbb/x;->s(Landroid/view/View;Z)Lbb/f0;

    .line 195
    .line 196
    .line 197
    move-result-object v6

    .line 198
    move/from16 v17, v11

    .line 199
    .line 200
    invoke-virtual {v0, v15, v10}, Lbb/x;->o(Landroid/view/View;Z)Lbb/f0;

    .line 201
    .line 202
    .line 203
    move-result-object v11

    .line 204
    invoke-static {v6, v11}, Lbb/h;->R(Lbb/f0;Lbb/f0;)La8/p1;

    .line 205
    .line 206
    .line 207
    move-result-object v6

    .line 208
    iget-boolean v6, v6, La8/p1;->a:Z

    .line 209
    .line 210
    if-nez v6, :cond_13

    .line 211
    .line 212
    new-instance v6, Landroid/graphics/Matrix;

    .line 213
    .line 214
    invoke-direct {v6}, Landroid/graphics/Matrix;-><init>()V

    .line 215
    .line 216
    .line 217
    invoke-virtual {v15}, Landroid/view/View;->getScrollX()I

    .line 218
    .line 219
    .line 220
    move-result v11

    .line 221
    neg-int v11, v11

    .line 222
    int-to-float v11, v11

    .line 223
    invoke-virtual {v15}, Landroid/view/View;->getScrollY()I

    .line 224
    .line 225
    .line 226
    move-result v12

    .line 227
    neg-int v12, v12

    .line 228
    int-to-float v12, v12

    .line 229
    invoke-virtual {v6, v11, v12}, Landroid/graphics/Matrix;->setTranslate(FF)V

    .line 230
    .line 231
    .line 232
    sget-object v11, Lbb/i0;->a:Lbb/b;

    .line 233
    .line 234
    invoke-virtual {v7, v6}, Landroid/view/View;->transformMatrixToGlobal(Landroid/graphics/Matrix;)V

    .line 235
    .line 236
    .line 237
    invoke-virtual {v1, v6}, Landroid/view/View;->transformMatrixToLocal(Landroid/graphics/Matrix;)V

    .line 238
    .line 239
    .line 240
    new-instance v11, Landroid/graphics/RectF;

    .line 241
    .line 242
    invoke-virtual {v7}, Landroid/view/View;->getWidth()I

    .line 243
    .line 244
    .line 245
    move-result v12

    .line 246
    int-to-float v12, v12

    .line 247
    invoke-virtual {v7}, Landroid/view/View;->getHeight()I

    .line 248
    .line 249
    .line 250
    move-result v15

    .line 251
    int-to-float v15, v15

    .line 252
    invoke-direct {v11, v9, v9, v12, v15}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {v6, v11}, Landroid/graphics/Matrix;->mapRect(Landroid/graphics/RectF;)Z

    .line 256
    .line 257
    .line 258
    iget v12, v11, Landroid/graphics/RectF;->left:F

    .line 259
    .line 260
    invoke-static {v12}, Ljava/lang/Math;->round(F)I

    .line 261
    .line 262
    .line 263
    move-result v12

    .line 264
    iget v15, v11, Landroid/graphics/RectF;->top:F

    .line 265
    .line 266
    invoke-static {v15}, Ljava/lang/Math;->round(F)I

    .line 267
    .line 268
    .line 269
    move-result v15

    .line 270
    move/from16 v18, v10

    .line 271
    .line 272
    iget v10, v11, Landroid/graphics/RectF;->right:F

    .line 273
    .line 274
    invoke-static {v10}, Ljava/lang/Math;->round(F)I

    .line 275
    .line 276
    .line 277
    move-result v10

    .line 278
    iget v13, v11, Landroid/graphics/RectF;->bottom:F

    .line 279
    .line 280
    invoke-static {v13}, Ljava/lang/Math;->round(F)I

    .line 281
    .line 282
    .line 283
    move-result v13

    .line 284
    new-instance v9, Landroid/widget/ImageView;

    .line 285
    .line 286
    invoke-virtual {v7}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 287
    .line 288
    .line 289
    move-result-object v5

    .line 290
    invoke-direct {v9, v5}, Landroid/widget/ImageView;-><init>(Landroid/content/Context;)V

    .line 291
    .line 292
    .line 293
    sget-object v5, Landroid/widget/ImageView$ScaleType;->CENTER_CROP:Landroid/widget/ImageView$ScaleType;

    .line 294
    .line 295
    invoke-virtual {v9, v5}, Landroid/widget/ImageView;->setScaleType(Landroid/widget/ImageView$ScaleType;)V

    .line 296
    .line 297
    .line 298
    invoke-virtual {v7}, Landroid/view/View;->isAttachedToWindow()Z

    .line 299
    .line 300
    .line 301
    move-result v5

    .line 302
    invoke-virtual {v1}, Landroid/view/View;->isAttachedToWindow()Z

    .line 303
    .line 304
    .line 305
    move-result v19

    .line 306
    if-nez v5, :cond_f

    .line 307
    .line 308
    if-nez v19, :cond_e

    .line 309
    .line 310
    move/from16 v22, v4

    .line 311
    .line 312
    move-object/from16 v21, v14

    .line 313
    .line 314
    move-object/from16 v0, v16

    .line 315
    .line 316
    goto/16 :goto_9

    .line 317
    .line 318
    :cond_e
    invoke-virtual {v7}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 319
    .line 320
    .line 321
    move-result-object v19

    .line 322
    move-object/from16 v8, v19

    .line 323
    .line 324
    check-cast v8, Landroid/view/ViewGroup;

    .line 325
    .line 326
    invoke-virtual {v8, v7}, Landroid/view/ViewGroup;->indexOfChild(Landroid/view/View;)I

    .line 327
    .line 328
    .line 329
    move-result v19

    .line 330
    move/from16 v20, v5

    .line 331
    .line 332
    invoke-virtual {v1}, Landroid/view/ViewGroup;->getOverlay()Landroid/view/ViewGroupOverlay;

    .line 333
    .line 334
    .line 335
    move-result-object v5

    .line 336
    invoke-virtual {v5, v7}, Landroid/view/ViewGroupOverlay;->add(Landroid/view/View;)V

    .line 337
    .line 338
    .line 339
    move/from16 v5, v19

    .line 340
    .line 341
    goto :goto_7

    .line 342
    :cond_f
    move/from16 v20, v5

    .line 343
    .line 344
    move-object/from16 v8, v16

    .line 345
    .line 346
    move/from16 v5, v17

    .line 347
    .line 348
    :goto_7
    invoke-virtual {v11}, Landroid/graphics/RectF;->width()F

    .line 349
    .line 350
    .line 351
    move-result v19

    .line 352
    move-object/from16 v21, v14

    .line 353
    .line 354
    invoke-static/range {v19 .. v19}, Ljava/lang/Math;->round(F)I

    .line 355
    .line 356
    .line 357
    move-result v14

    .line 358
    invoke-virtual {v11}, Landroid/graphics/RectF;->height()F

    .line 359
    .line 360
    .line 361
    move-result v19

    .line 362
    move/from16 v22, v4

    .line 363
    .line 364
    invoke-static/range {v19 .. v19}, Ljava/lang/Math;->round(F)I

    .line 365
    .line 366
    .line 367
    move-result v4

    .line 368
    if-lez v14, :cond_10

    .line 369
    .line 370
    if-lez v4, :cond_10

    .line 371
    .line 372
    mul-int v3, v14, v4

    .line 373
    .line 374
    int-to-float v3, v3

    .line 375
    const/high16 v19, 0x49800000    # 1048576.0f

    .line 376
    .line 377
    div-float v3, v19, v3

    .line 378
    .line 379
    const/high16 v0, 0x3f800000    # 1.0f

    .line 380
    .line 381
    invoke-static {v0, v3}, Ljava/lang/Math;->min(FF)F

    .line 382
    .line 383
    .line 384
    move-result v3

    .line 385
    int-to-float v0, v14

    .line 386
    mul-float/2addr v0, v3

    .line 387
    invoke-static {v0}, Ljava/lang/Math;->round(F)I

    .line 388
    .line 389
    .line 390
    move-result v0

    .line 391
    int-to-float v4, v4

    .line 392
    mul-float/2addr v4, v3

    .line 393
    invoke-static {v4}, Ljava/lang/Math;->round(F)I

    .line 394
    .line 395
    .line 396
    move-result v4

    .line 397
    iget v14, v11, Landroid/graphics/RectF;->left:F

    .line 398
    .line 399
    neg-float v14, v14

    .line 400
    iget v11, v11, Landroid/graphics/RectF;->top:F

    .line 401
    .line 402
    neg-float v11, v11

    .line 403
    invoke-virtual {v6, v14, v11}, Landroid/graphics/Matrix;->postTranslate(FF)Z

    .line 404
    .line 405
    .line 406
    invoke-virtual {v6, v3, v3}, Landroid/graphics/Matrix;->postScale(FF)Z

    .line 407
    .line 408
    .line 409
    new-instance v3, Landroid/graphics/Picture;

    .line 410
    .line 411
    invoke-direct {v3}, Landroid/graphics/Picture;-><init>()V

    .line 412
    .line 413
    .line 414
    invoke-virtual {v3, v0, v4}, Landroid/graphics/Picture;->beginRecording(II)Landroid/graphics/Canvas;

    .line 415
    .line 416
    .line 417
    move-result-object v0

    .line 418
    invoke-virtual {v0, v6}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 419
    .line 420
    .line 421
    invoke-virtual {v7, v0}, Landroid/view/View;->draw(Landroid/graphics/Canvas;)V

    .line 422
    .line 423
    .line 424
    invoke-virtual {v3}, Landroid/graphics/Picture;->endRecording()V

    .line 425
    .line 426
    .line 427
    invoke-static {v3}, Lbb/e0;->a(Landroid/graphics/Picture;)Landroid/graphics/Bitmap;

    .line 428
    .line 429
    .line 430
    move-result-object v0

    .line 431
    goto :goto_8

    .line 432
    :cond_10
    move-object/from16 v0, v16

    .line 433
    .line 434
    :goto_8
    if-nez v20, :cond_11

    .line 435
    .line 436
    invoke-virtual {v1}, Landroid/view/ViewGroup;->getOverlay()Landroid/view/ViewGroupOverlay;

    .line 437
    .line 438
    .line 439
    move-result-object v3

    .line 440
    invoke-virtual {v3, v7}, Landroid/view/ViewGroupOverlay;->remove(Landroid/view/View;)V

    .line 441
    .line 442
    .line 443
    invoke-virtual {v8, v7, v5}, Landroid/view/ViewGroup;->addView(Landroid/view/View;I)V

    .line 444
    .line 445
    .line 446
    :cond_11
    :goto_9
    if-eqz v0, :cond_12

    .line 447
    .line 448
    invoke-virtual {v9, v0}, Landroid/widget/ImageView;->setImageBitmap(Landroid/graphics/Bitmap;)V

    .line 449
    .line 450
    .line 451
    :cond_12
    sub-int v0, v10, v12

    .line 452
    .line 453
    const/high16 v3, 0x40000000    # 2.0f

    .line 454
    .line 455
    invoke-static {v0, v3}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 456
    .line 457
    .line 458
    move-result v0

    .line 459
    sub-int v4, v13, v15

    .line 460
    .line 461
    invoke-static {v4, v3}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 462
    .line 463
    .line 464
    move-result v3

    .line 465
    invoke-virtual {v9, v0, v3}, Landroid/view/View;->measure(II)V

    .line 466
    .line 467
    .line 468
    invoke-virtual {v9, v12, v15, v10, v13}, Landroid/view/View;->layout(IIII)V

    .line 469
    .line 470
    .line 471
    move-object v14, v9

    .line 472
    :goto_a
    move/from16 v10, v17

    .line 473
    .line 474
    move-object/from16 v6, v21

    .line 475
    .line 476
    goto :goto_c

    .line 477
    :cond_13
    move/from16 v22, v4

    .line 478
    .line 479
    move/from16 v18, v10

    .line 480
    .line 481
    move-object/from16 v21, v14

    .line 482
    .line 483
    invoke-virtual {v15}, Landroid/view/View;->getId()I

    .line 484
    .line 485
    .line 486
    move-result v0

    .line 487
    invoke-virtual {v15}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 488
    .line 489
    .line 490
    move-result-object v3

    .line 491
    if-nez v3, :cond_15

    .line 492
    .line 493
    const/4 v3, -0x1

    .line 494
    if-eq v0, v3, :cond_15

    .line 495
    .line 496
    invoke-virtual {v1, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 497
    .line 498
    .line 499
    goto :goto_b

    .line 500
    :cond_14
    move/from16 v22, v4

    .line 501
    .line 502
    move/from16 v18, v10

    .line 503
    .line 504
    move/from16 v17, v11

    .line 505
    .line 506
    move-object/from16 v21, v14

    .line 507
    .line 508
    const/16 v16, 0x0

    .line 509
    .line 510
    :cond_15
    :goto_b
    move-object v14, v12

    .line 511
    goto :goto_a

    .line 512
    :goto_c
    if-eqz v14, :cond_1a

    .line 513
    .line 514
    if-nez v10, :cond_16

    .line 515
    .line 516
    iget-object v0, v2, Lbb/f0;->a:Ljava/util/HashMap;

    .line 517
    .line 518
    const-string v3, "android:visibility:screenLocation"

    .line 519
    .line 520
    invoke-virtual {v0, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 521
    .line 522
    .line 523
    move-result-object v0

    .line 524
    check-cast v0, [I

    .line 525
    .line 526
    aget v3, v0, v17

    .line 527
    .line 528
    aget v0, v0, v18

    .line 529
    .line 530
    const/4 v4, 0x2

    .line 531
    new-array v4, v4, [I

    .line 532
    .line 533
    invoke-virtual {v1, v4}, Landroid/view/View;->getLocationOnScreen([I)V

    .line 534
    .line 535
    .line 536
    aget v5, v4, v17

    .line 537
    .line 538
    sub-int/2addr v3, v5

    .line 539
    invoke-virtual {v14}, Landroid/view/View;->getLeft()I

    .line 540
    .line 541
    .line 542
    move-result v5

    .line 543
    sub-int/2addr v3, v5

    .line 544
    invoke-virtual {v14, v3}, Landroid/view/View;->offsetLeftAndRight(I)V

    .line 545
    .line 546
    .line 547
    aget v3, v4, v18

    .line 548
    .line 549
    sub-int/2addr v0, v3

    .line 550
    invoke-virtual {v14}, Landroid/view/View;->getTop()I

    .line 551
    .line 552
    .line 553
    move-result v3

    .line 554
    sub-int/2addr v0, v3

    .line 555
    invoke-virtual {v14, v0}, Landroid/view/View;->offsetTopAndBottom(I)V

    .line 556
    .line 557
    .line 558
    invoke-virtual {v1}, Landroid/view/ViewGroup;->getOverlay()Landroid/view/ViewGroupOverlay;

    .line 559
    .line 560
    .line 561
    move-result-object v0

    .line 562
    invoke-virtual {v0, v14}, Landroid/view/ViewGroupOverlay;->add(Landroid/view/View;)V

    .line 563
    .line 564
    .line 565
    :cond_16
    sget-object v0, Lbb/i0;->a:Lbb/b;

    .line 566
    .line 567
    const/high16 v0, 0x3f800000    # 1.0f

    .line 568
    .line 569
    invoke-static {v2, v0}, Lbb/h;->Q(Lbb/f0;F)F

    .line 570
    .line 571
    .line 572
    move-result v2

    .line 573
    const/4 v4, 0x0

    .line 574
    move-object/from16 v3, p0

    .line 575
    .line 576
    invoke-virtual {v3, v14, v2, v4}, Lbb/h;->P(Landroid/view/View;FF)Landroid/animation/ObjectAnimator;

    .line 577
    .line 578
    .line 579
    move-result-object v2

    .line 580
    if-nez v2, :cond_17

    .line 581
    .line 582
    move-object/from16 v4, p3

    .line 583
    .line 584
    invoke-static {v4, v0}, Lbb/h;->Q(Lbb/f0;F)F

    .line 585
    .line 586
    .line 587
    move-result v0

    .line 588
    invoke-virtual {v14, v0}, Landroid/view/View;->setTransitionAlpha(F)V

    .line 589
    .line 590
    .line 591
    :cond_17
    if-nez v10, :cond_19

    .line 592
    .line 593
    if-nez v2, :cond_18

    .line 594
    .line 595
    invoke-virtual {v1}, Landroid/view/ViewGroup;->getOverlay()Landroid/view/ViewGroupOverlay;

    .line 596
    .line 597
    .line 598
    move-result-object v0

    .line 599
    invoke-virtual {v0, v14}, Landroid/view/ViewGroupOverlay;->remove(Landroid/view/View;)V

    .line 600
    .line 601
    .line 602
    return-object v2

    .line 603
    :cond_18
    const v0, 0x7f0a027b

    .line 604
    .line 605
    .line 606
    invoke-virtual {v7, v0, v14}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 607
    .line 608
    .line 609
    new-instance v0, Lbb/m0;

    .line 610
    .line 611
    invoke-direct {v0, v3, v1, v14, v7}, Lbb/m0;-><init>(Lbb/h;Landroid/view/ViewGroup;Landroid/view/View;Landroid/view/View;)V

    .line 612
    .line 613
    .line 614
    invoke-virtual {v2, v0}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 615
    .line 616
    .line 617
    invoke-virtual {v2, v0}, Landroid/animation/Animator;->addPauseListener(Landroid/animation/Animator$AnimatorPauseListener;)V

    .line 618
    .line 619
    .line 620
    invoke-virtual {v3}, Lbb/x;->p()Lbb/x;

    .line 621
    .line 622
    .line 623
    move-result-object v1

    .line 624
    invoke-virtual {v1, v0}, Lbb/x;->a(Lbb/v;)V

    .line 625
    .line 626
    .line 627
    :cond_19
    return-object v2

    .line 628
    :cond_1a
    move-object/from16 v3, p0

    .line 629
    .line 630
    move-object/from16 v4, p3

    .line 631
    .line 632
    if-eqz v6, :cond_1d

    .line 633
    .line 634
    invoke-virtual {v6}, Landroid/view/View;->getVisibility()I

    .line 635
    .line 636
    .line 637
    move-result v0

    .line 638
    sget-object v1, Lbb/i0;->a:Lbb/b;

    .line 639
    .line 640
    move/from16 v1, v17

    .line 641
    .line 642
    invoke-virtual {v6, v1}, Landroid/view/View;->setTransitionVisibility(I)V

    .line 643
    .line 644
    .line 645
    const/high16 v1, 0x3f800000    # 1.0f

    .line 646
    .line 647
    invoke-static {v2, v1}, Lbb/h;->Q(Lbb/f0;F)F

    .line 648
    .line 649
    .line 650
    move-result v2

    .line 651
    const/4 v5, 0x0

    .line 652
    invoke-virtual {v3, v6, v2, v5}, Lbb/h;->P(Landroid/view/View;FF)Landroid/animation/ObjectAnimator;

    .line 653
    .line 654
    .line 655
    move-result-object v2

    .line 656
    if-nez v2, :cond_1b

    .line 657
    .line 658
    invoke-static {v4, v1}, Lbb/h;->Q(Lbb/f0;F)F

    .line 659
    .line 660
    .line 661
    move-result v1

    .line 662
    invoke-virtual {v6, v1}, Landroid/view/View;->setTransitionAlpha(F)V

    .line 663
    .line 664
    .line 665
    :cond_1b
    if-eqz v2, :cond_1c

    .line 666
    .line 667
    new-instance v0, Lbb/l0;

    .line 668
    .line 669
    move/from16 v1, v22

    .line 670
    .line 671
    invoke-direct {v0, v6, v1}, Lbb/l0;-><init>(Landroid/view/View;I)V

    .line 672
    .line 673
    .line 674
    invoke-virtual {v2, v0}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 675
    .line 676
    .line 677
    invoke-virtual {v3}, Lbb/x;->p()Lbb/x;

    .line 678
    .line 679
    .line 680
    move-result-object v1

    .line 681
    invoke-virtual {v1, v0}, Lbb/x;->a(Lbb/v;)V

    .line 682
    .line 683
    .line 684
    return-object v2

    .line 685
    :cond_1c
    invoke-virtual {v6, v0}, Landroid/view/View;->setTransitionVisibility(I)V

    .line 686
    .line 687
    .line 688
    return-object v2

    .line 689
    :cond_1d
    :goto_d
    return-object v16
.end method

.method public final r()[Ljava/lang/String;
    .locals 0

    .line 1
    sget-object p0, Lbb/h;->I:[Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final u()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final v(Lbb/f0;Lbb/f0;)Z
    .locals 2

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    if-nez p2, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    if-eqz p1, :cond_1

    .line 7
    .line 8
    if-eqz p2, :cond_1

    .line 9
    .line 10
    iget-object p0, p2, Lbb/f0;->a:Ljava/util/HashMap;

    .line 11
    .line 12
    const-string v0, "android:visibility:visibility"

    .line 13
    .line 14
    invoke-virtual {p0, v0}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    iget-object v1, p1, Lbb/f0;->a:Ljava/util/HashMap;

    .line 19
    .line 20
    invoke-virtual {v1, v0}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eq p0, v0, :cond_1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    invoke-static {p1, p2}, Lbb/h;->R(Lbb/f0;Lbb/f0;)La8/p1;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    iget-boolean p1, p0, La8/p1;->a:Z

    .line 32
    .line 33
    if-eqz p1, :cond_3

    .line 34
    .line 35
    iget p1, p0, La8/p1;->c:I

    .line 36
    .line 37
    if-eqz p1, :cond_2

    .line 38
    .line 39
    iget p0, p0, La8/p1;->d:I

    .line 40
    .line 41
    if-nez p0, :cond_3

    .line 42
    .line 43
    :cond_2
    const/4 p0, 0x1

    .line 44
    return p0

    .line 45
    :cond_3
    :goto_0
    const/4 p0, 0x0

    .line 46
    return p0
.end method
