.class public final Lcom/google/android/material/timepicker/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/material/timepicker/f;
.implements Lcom/google/android/material/timepicker/o;


# static fields
.field public static final i:[Ljava/lang/String;

.field public static final j:[Ljava/lang/String;

.field public static final k:[Ljava/lang/String;


# instance fields
.field public final d:Lcom/google/android/material/timepicker/TimePickerView;

.field public final e:Lcom/google/android/material/timepicker/l;

.field public f:F

.field public g:F

.field public h:Z


# direct methods
.method static constructor <clinit>()V
    .locals 25

    .line 1
    const-string v10, "10"

    .line 2
    .line 3
    const-string v11, "11"

    .line 4
    .line 5
    const-string v0, "12"

    .line 6
    .line 7
    const-string v1, "1"

    .line 8
    .line 9
    const-string v2, "2"

    .line 10
    .line 11
    const-string v3, "3"

    .line 12
    .line 13
    const-string v4, "4"

    .line 14
    .line 15
    const-string v5, "5"

    .line 16
    .line 17
    const-string v6, "6"

    .line 18
    .line 19
    const-string v7, "7"

    .line 20
    .line 21
    const-string v8, "8"

    .line 22
    .line 23
    const-string v9, "9"

    .line 24
    .line 25
    filled-new-array/range {v0 .. v11}, [Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    sput-object v0, Lcom/google/android/material/timepicker/n;->i:[Ljava/lang/String;

    .line 30
    .line 31
    const-string v23, "22"

    .line 32
    .line 33
    const-string v24, "23"

    .line 34
    .line 35
    const-string v1, "00"

    .line 36
    .line 37
    const-string v2, "1"

    .line 38
    .line 39
    const-string v3, "2"

    .line 40
    .line 41
    const-string v4, "3"

    .line 42
    .line 43
    const-string v5, "4"

    .line 44
    .line 45
    const-string v6, "5"

    .line 46
    .line 47
    const-string v7, "6"

    .line 48
    .line 49
    const-string v8, "7"

    .line 50
    .line 51
    const-string v9, "8"

    .line 52
    .line 53
    const-string v10, "9"

    .line 54
    .line 55
    const-string v11, "10"

    .line 56
    .line 57
    const-string v12, "11"

    .line 58
    .line 59
    const-string v13, "12"

    .line 60
    .line 61
    const-string v14, "13"

    .line 62
    .line 63
    const-string v15, "14"

    .line 64
    .line 65
    const-string v16, "15"

    .line 66
    .line 67
    const-string v17, "16"

    .line 68
    .line 69
    const-string v18, "17"

    .line 70
    .line 71
    const-string v19, "18"

    .line 72
    .line 73
    const-string v20, "19"

    .line 74
    .line 75
    const-string v21, "20"

    .line 76
    .line 77
    const-string v22, "21"

    .line 78
    .line 79
    filled-new-array/range {v1 .. v24}, [Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    sput-object v0, Lcom/google/android/material/timepicker/n;->j:[Ljava/lang/String;

    .line 84
    .line 85
    const-string v11, "50"

    .line 86
    .line 87
    const-string v12, "55"

    .line 88
    .line 89
    const-string v1, "00"

    .line 90
    .line 91
    const-string v2, "5"

    .line 92
    .line 93
    const-string v3, "10"

    .line 94
    .line 95
    const-string v4, "15"

    .line 96
    .line 97
    const-string v5, "20"

    .line 98
    .line 99
    const-string v6, "25"

    .line 100
    .line 101
    const-string v7, "30"

    .line 102
    .line 103
    const-string v8, "35"

    .line 104
    .line 105
    const-string v9, "40"

    .line 106
    .line 107
    const-string v10, "45"

    .line 108
    .line 109
    filled-new-array/range {v1 .. v12}, [Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    sput-object v0, Lcom/google/android/material/timepicker/n;->k:[Ljava/lang/String;

    .line 114
    .line 115
    return-void
.end method

.method public constructor <init>(Lcom/google/android/material/timepicker/TimePickerView;Lcom/google/android/material/timepicker/l;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Lcom/google/android/material/timepicker/n;->h:Z

    .line 6
    .line 7
    iput-object p1, p0, Lcom/google/android/material/timepicker/n;->d:Lcom/google/android/material/timepicker/TimePickerView;

    .line 8
    .line 9
    iput-object p2, p0, Lcom/google/android/material/timepicker/n;->e:Lcom/google/android/material/timepicker/l;

    .line 10
    .line 11
    iget p2, p2, Lcom/google/android/material/timepicker/l;->f:I

    .line 12
    .line 13
    if-nez p2, :cond_0

    .line 14
    .line 15
    iget-object p2, p1, Lcom/google/android/material/timepicker/TimePickerView;->h:Lcom/google/android/material/button/MaterialButtonToggleGroup;

    .line 16
    .line 17
    invoke-virtual {p2, v0}, Landroid/view/View;->setVisibility(I)V

    .line 18
    .line 19
    .line 20
    :cond_0
    iget-object p2, p1, Lcom/google/android/material/timepicker/TimePickerView;->f:Lcom/google/android/material/timepicker/ClockHandView;

    .line 21
    .line 22
    iget-object p2, p2, Lcom/google/android/material/timepicker/ClockHandView;->m:Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-virtual {p2, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    iput-object p0, p1, Lcom/google/android/material/timepicker/TimePickerView;->j:Lcom/google/android/material/timepicker/n;

    .line 28
    .line 29
    iput-object p0, p1, Lcom/google/android/material/timepicker/TimePickerView;->i:Lcom/google/android/material/timepicker/n;

    .line 30
    .line 31
    iget-object p1, p1, Lcom/google/android/material/timepicker/TimePickerView;->f:Lcom/google/android/material/timepicker/ClockHandView;

    .line 32
    .line 33
    iput-object p0, p1, Lcom/google/android/material/timepicker/ClockHandView;->u:Lcom/google/android/material/timepicker/n;

    .line 34
    .line 35
    const-string p1, "%d"

    .line 36
    .line 37
    sget-object p2, Lcom/google/android/material/timepicker/n;->i:[Ljava/lang/String;

    .line 38
    .line 39
    invoke-virtual {p0, p1, p2}, Lcom/google/android/material/timepicker/n;->f(Ljava/lang/String;[Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    sget-object p2, Lcom/google/android/material/timepicker/n;->j:[Ljava/lang/String;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Lcom/google/android/material/timepicker/n;->f(Ljava/lang/String;[Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    sget-object p1, Lcom/google/android/material/timepicker/n;->k:[Ljava/lang/String;

    .line 48
    .line 49
    const-string p2, "%02d"

    .line 50
    .line 51
    invoke-virtual {p0, p2, p1}, Lcom/google/android/material/timepicker/n;->f(Ljava/lang/String;[Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {p0}, Lcom/google/android/material/timepicker/n;->invalidate()V

    .line 55
    .line 56
    .line 57
    return-void
.end method


# virtual methods
.method public final a(FZ)V
    .locals 6

    .line 1
    iget-boolean v0, p0, Lcom/google/android/material/timepicker/n;->h:Z

    .line 2
    .line 3
    if-nez v0, :cond_4

    .line 4
    .line 5
    if-eqz p2, :cond_0

    .line 6
    .line 7
    goto :goto_1

    .line 8
    :cond_0
    iget-object p2, p0, Lcom/google/android/material/timepicker/n;->e:Lcom/google/android/material/timepicker/l;

    .line 9
    .line 10
    iget v0, p2, Lcom/google/android/material/timepicker/l;->g:I

    .line 11
    .line 12
    iget v1, p2, Lcom/google/android/material/timepicker/l;->h:I

    .line 13
    .line 14
    invoke-static {p1}, Ljava/lang/Math;->round(F)I

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    iget v2, p2, Lcom/google/android/material/timepicker/l;->i:I

    .line 19
    .line 20
    iget-object v3, p0, Lcom/google/android/material/timepicker/n;->d:Lcom/google/android/material/timepicker/TimePickerView;

    .line 21
    .line 22
    const/16 v4, 0xc

    .line 23
    .line 24
    if-ne v2, v4, :cond_1

    .line 25
    .line 26
    add-int/lit8 p1, p1, 0x3

    .line 27
    .line 28
    div-int/lit8 p1, p1, 0x6

    .line 29
    .line 30
    invoke-virtual {p2, p1}, Lcom/google/android/material/timepicker/l;->j(I)V

    .line 31
    .line 32
    .line 33
    iget p1, p2, Lcom/google/android/material/timepicker/l;->h:I

    .line 34
    .line 35
    mul-int/lit8 p1, p1, 0x6

    .line 36
    .line 37
    int-to-double v4, p1

    .line 38
    invoke-static {v4, v5}, Ljava/lang/Math;->floor(D)D

    .line 39
    .line 40
    .line 41
    move-result-wide v4

    .line 42
    double-to-float p1, v4

    .line 43
    iput p1, p0, Lcom/google/android/material/timepicker/n;->f:F

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_1
    add-int/lit8 p1, p1, 0xf

    .line 47
    .line 48
    div-int/lit8 p1, p1, 0x1e

    .line 49
    .line 50
    iget v2, p2, Lcom/google/android/material/timepicker/l;->f:I

    .line 51
    .line 52
    const/4 v4, 0x1

    .line 53
    if-ne v2, v4, :cond_2

    .line 54
    .line 55
    rem-int/lit8 p1, p1, 0xc

    .line 56
    .line 57
    iget-object v2, v3, Lcom/google/android/material/timepicker/TimePickerView;->g:Lcom/google/android/material/timepicker/ClockFaceView;

    .line 58
    .line 59
    iget-object v2, v2, Lcom/google/android/material/timepicker/ClockFaceView;->g:Lcom/google/android/material/timepicker/ClockHandView;

    .line 60
    .line 61
    iget v2, v2, Lcom/google/android/material/timepicker/ClockHandView;->x:I

    .line 62
    .line 63
    const/4 v4, 0x2

    .line 64
    if-ne v2, v4, :cond_2

    .line 65
    .line 66
    add-int/lit8 p1, p1, 0xc

    .line 67
    .line 68
    :cond_2
    invoke-virtual {p2, p1}, Lcom/google/android/material/timepicker/l;->i(I)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p2}, Lcom/google/android/material/timepicker/l;->h()I

    .line 72
    .line 73
    .line 74
    move-result p1

    .line 75
    mul-int/lit8 p1, p1, 0x1e

    .line 76
    .line 77
    rem-int/lit16 p1, p1, 0x168

    .line 78
    .line 79
    int-to-float p1, p1

    .line 80
    iput p1, p0, Lcom/google/android/material/timepicker/n;->g:F

    .line 81
    .line 82
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/material/timepicker/n;->e()V

    .line 83
    .line 84
    .line 85
    iget p0, p2, Lcom/google/android/material/timepicker/l;->h:I

    .line 86
    .line 87
    if-ne p0, v1, :cond_3

    .line 88
    .line 89
    iget p0, p2, Lcom/google/android/material/timepicker/l;->g:I

    .line 90
    .line 91
    if-eq p0, v0, :cond_4

    .line 92
    .line 93
    :cond_3
    const/4 p0, 0x4

    .line 94
    invoke-virtual {v3, p0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 95
    .line 96
    .line 97
    :cond_4
    :goto_1
    return-void
.end method

.method public final b()V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/android/material/timepicker/n;->d:Lcom/google/android/material/timepicker/TimePickerView;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-virtual {p0, v0}, Landroid/view/View;->setVisibility(I)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final c()V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/android/material/timepicker/n;->d:Lcom/google/android/material/timepicker/TimePickerView;

    .line 2
    .line 3
    const/16 v0, 0x8

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Landroid/view/View;->setVisibility(I)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final d(IZ)V
    .locals 13

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    const/16 v2, 0xc

    .line 4
    .line 5
    if-ne p1, v2, :cond_0

    .line 6
    .line 7
    move v3, v1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v3, v0

    .line 10
    :goto_0
    iget-object v4, p0, Lcom/google/android/material/timepicker/n;->d:Lcom/google/android/material/timepicker/TimePickerView;

    .line 11
    .line 12
    iget-object v5, v4, Lcom/google/android/material/timepicker/TimePickerView;->f:Lcom/google/android/material/timepicker/ClockHandView;

    .line 13
    .line 14
    iget-object v6, v4, Lcom/google/android/material/timepicker/TimePickerView;->e:Lcom/google/android/material/chip/Chip;

    .line 15
    .line 16
    iget-object v7, v4, Lcom/google/android/material/timepicker/TimePickerView;->d:Lcom/google/android/material/chip/Chip;

    .line 17
    .line 18
    iget-object v8, v4, Lcom/google/android/material/timepicker/TimePickerView;->g:Lcom/google/android/material/timepicker/ClockFaceView;

    .line 19
    .line 20
    iput-boolean v3, v5, Lcom/google/android/material/timepicker/ClockHandView;->g:Z

    .line 21
    .line 22
    iget-object v5, p0, Lcom/google/android/material/timepicker/n;->e:Lcom/google/android/material/timepicker/l;

    .line 23
    .line 24
    iput p1, v5, Lcom/google/android/material/timepicker/l;->i:I

    .line 25
    .line 26
    iget v9, v5, Lcom/google/android/material/timepicker/l;->f:I

    .line 27
    .line 28
    if-eqz v3, :cond_1

    .line 29
    .line 30
    sget-object v10, Lcom/google/android/material/timepicker/n;->k:[Ljava/lang/String;

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_1
    if-ne v9, v1, :cond_2

    .line 34
    .line 35
    sget-object v10, Lcom/google/android/material/timepicker/n;->j:[Ljava/lang/String;

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_2
    sget-object v10, Lcom/google/android/material/timepicker/n;->i:[Ljava/lang/String;

    .line 39
    .line 40
    :goto_1
    if-eqz v3, :cond_3

    .line 41
    .line 42
    const v11, 0x7f12071a

    .line 43
    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_3
    if-ne v9, v1, :cond_4

    .line 47
    .line 48
    const v11, 0x7f120716

    .line 49
    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_4
    const v11, 0x7f120718

    .line 53
    .line 54
    .line 55
    :goto_2
    invoke-virtual {v8, v10, v11}, Lcom/google/android/material/timepicker/ClockFaceView;->l([Ljava/lang/String;I)V

    .line 56
    .line 57
    .line 58
    iget v10, v5, Lcom/google/android/material/timepicker/l;->i:I

    .line 59
    .line 60
    const/4 v11, 0x2

    .line 61
    const/16 v12, 0xa

    .line 62
    .line 63
    if-ne v10, v12, :cond_5

    .line 64
    .line 65
    if-ne v9, v1, :cond_5

    .line 66
    .line 67
    iget v5, v5, Lcom/google/android/material/timepicker/l;->g:I

    .line 68
    .line 69
    if-lt v5, v2, :cond_5

    .line 70
    .line 71
    move v5, v11

    .line 72
    goto :goto_3

    .line 73
    :cond_5
    move v5, v1

    .line 74
    :goto_3
    iget-object v8, v8, Lcom/google/android/material/timepicker/ClockFaceView;->g:Lcom/google/android/material/timepicker/ClockHandView;

    .line 75
    .line 76
    iput v5, v8, Lcom/google/android/material/timepicker/ClockHandView;->x:I

    .line 77
    .line 78
    invoke-virtual {v8}, Landroid/view/View;->invalidate()V

    .line 79
    .line 80
    .line 81
    if-eqz v3, :cond_6

    .line 82
    .line 83
    iget v3, p0, Lcom/google/android/material/timepicker/n;->f:F

    .line 84
    .line 85
    goto :goto_4

    .line 86
    :cond_6
    iget v3, p0, Lcom/google/android/material/timepicker/n;->g:F

    .line 87
    .line 88
    :goto_4
    iget-object v5, v4, Lcom/google/android/material/timepicker/TimePickerView;->f:Lcom/google/android/material/timepicker/ClockHandView;

    .line 89
    .line 90
    invoke-virtual {v5, v3, p2}, Lcom/google/android/material/timepicker/ClockHandView;->c(FZ)V

    .line 91
    .line 92
    .line 93
    if-ne p1, v2, :cond_7

    .line 94
    .line 95
    move p2, v1

    .line 96
    goto :goto_5

    .line 97
    :cond_7
    move p2, v0

    .line 98
    :goto_5
    invoke-virtual {v7, p2}, Lcom/google/android/material/chip/Chip;->setChecked(Z)V

    .line 99
    .line 100
    .line 101
    if-eqz p2, :cond_8

    .line 102
    .line 103
    move p2, v11

    .line 104
    goto :goto_6

    .line 105
    :cond_8
    move p2, v0

    .line 106
    :goto_6
    invoke-virtual {v7, p2}, Landroid/view/View;->setAccessibilityLiveRegion(I)V

    .line 107
    .line 108
    .line 109
    if-ne p1, v12, :cond_9

    .line 110
    .line 111
    goto :goto_7

    .line 112
    :cond_9
    move v1, v0

    .line 113
    :goto_7
    invoke-virtual {v6, v1}, Lcom/google/android/material/chip/Chip;->setChecked(Z)V

    .line 114
    .line 115
    .line 116
    if-eqz v1, :cond_a

    .line 117
    .line 118
    move v0, v11

    .line 119
    :cond_a
    invoke-virtual {v6, v0}, Landroid/view/View;->setAccessibilityLiveRegion(I)V

    .line 120
    .line 121
    .line 122
    new-instance p1, Lcom/google/android/material/timepicker/m;

    .line 123
    .line 124
    invoke-virtual {v4}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 125
    .line 126
    .line 127
    move-result-object p2

    .line 128
    const/4 v0, 0x0

    .line 129
    invoke-direct {p1, p0, p2, v0}, Lcom/google/android/material/timepicker/m;-><init>(Lcom/google/android/material/timepicker/n;Landroid/content/Context;I)V

    .line 130
    .line 131
    .line 132
    invoke-static {v6, p1}, Ld6/r0;->i(Landroid/view/View;Ld6/b;)V

    .line 133
    .line 134
    .line 135
    new-instance p1, Lcom/google/android/material/timepicker/m;

    .line 136
    .line 137
    invoke-virtual {v4}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 138
    .line 139
    .line 140
    move-result-object p2

    .line 141
    const/4 v0, 0x1

    .line 142
    invoke-direct {p1, p0, p2, v0}, Lcom/google/android/material/timepicker/m;-><init>(Lcom/google/android/material/timepicker/n;Landroid/content/Context;I)V

    .line 143
    .line 144
    .line 145
    invoke-static {v7, p1}, Ld6/r0;->i(Landroid/view/View;Ld6/b;)V

    .line 146
    .line 147
    .line 148
    return-void
.end method

.method public final e()V
    .locals 7

    .line 1
    iget-object v0, p0, Lcom/google/android/material/timepicker/n;->e:Lcom/google/android/material/timepicker/l;

    .line 2
    .line 3
    iget v1, v0, Lcom/google/android/material/timepicker/l;->j:I

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/google/android/material/timepicker/l;->h()I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    iget v0, v0, Lcom/google/android/material/timepicker/l;->h:I

    .line 10
    .line 11
    iget-object p0, p0, Lcom/google/android/material/timepicker/n;->d:Lcom/google/android/material/timepicker/TimePickerView;

    .line 12
    .line 13
    iget-object v3, p0, Lcom/google/android/material/timepicker/TimePickerView;->e:Lcom/google/android/material/chip/Chip;

    .line 14
    .line 15
    iget-object v4, p0, Lcom/google/android/material/timepicker/TimePickerView;->d:Lcom/google/android/material/chip/Chip;

    .line 16
    .line 17
    const/4 v5, 0x1

    .line 18
    if-ne v1, v5, :cond_0

    .line 19
    .line 20
    const v1, 0x7f0a01bf

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const v1, 0x7f0a01be

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object v6, p0, Lcom/google/android/material/timepicker/TimePickerView;->h:Lcom/google/android/material/button/MaterialButtonToggleGroup;

    .line 28
    .line 29
    invoke-virtual {v6, v1, v5}, Lcom/google/android/material/button/MaterialButtonToggleGroup;->f(IZ)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-virtual {p0}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    iget-object p0, p0, Landroid/content/res/Configuration;->locale:Ljava/util/Locale;

    .line 41
    .line 42
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    const-string v1, "%02d"

    .line 51
    .line 52
    invoke-static {p0, v1, v0}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    invoke-static {p0, v1, v2}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-virtual {v4}, Landroid/widget/TextView;->getText()Ljava/lang/CharSequence;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    invoke-static {v1, v0}, Landroid/text/TextUtils;->equals(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-nez v1, :cond_1

    .line 77
    .line 78
    invoke-virtual {v4, v0}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 79
    .line 80
    .line 81
    :cond_1
    invoke-virtual {v3}, Landroid/widget/TextView;->getText()Ljava/lang/CharSequence;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    invoke-static {v0, p0}, Landroid/text/TextUtils;->equals(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    if-nez v0, :cond_2

    .line 90
    .line 91
    invoke-virtual {v3, p0}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 92
    .line 93
    .line 94
    :cond_2
    return-void
.end method

.method public final f(Ljava/lang/String;[Ljava/lang/String;)V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    array-length v1, p2

    .line 3
    if-ge v0, v1, :cond_0

    .line 4
    .line 5
    iget-object v1, p0, Lcom/google/android/material/timepicker/n;->d:Lcom/google/android/material/timepicker/TimePickerView;

    .line 6
    .line 7
    invoke-virtual {v1}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    aget-object v2, p2, v0

    .line 12
    .line 13
    invoke-static {v1, v2, p1}, Lcom/google/android/material/timepicker/l;->a(Landroid/content/res/Resources;Ljava/lang/CharSequence;Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    aput-object v1, p2, v0

    .line 18
    .line 19
    add-int/lit8 v0, v0, 0x1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    return-void
.end method

.method public final invalidate()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/material/timepicker/n;->e:Lcom/google/android/material/timepicker/l;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/material/timepicker/l;->h()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    mul-int/lit8 v1, v1, 0x1e

    .line 8
    .line 9
    rem-int/lit16 v1, v1, 0x168

    .line 10
    .line 11
    int-to-float v1, v1

    .line 12
    iput v1, p0, Lcom/google/android/material/timepicker/n;->g:F

    .line 13
    .line 14
    iget v1, v0, Lcom/google/android/material/timepicker/l;->h:I

    .line 15
    .line 16
    mul-int/lit8 v1, v1, 0x6

    .line 17
    .line 18
    int-to-float v1, v1

    .line 19
    iput v1, p0, Lcom/google/android/material/timepicker/n;->f:F

    .line 20
    .line 21
    iget v0, v0, Lcom/google/android/material/timepicker/l;->i:I

    .line 22
    .line 23
    const/4 v1, 0x0

    .line 24
    invoke-virtual {p0, v0, v1}, Lcom/google/android/material/timepicker/n;->d(IZ)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Lcom/google/android/material/timepicker/n;->e()V

    .line 28
    .line 29
    .line 30
    return-void
.end method
