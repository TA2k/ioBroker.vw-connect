.class public final Lp3/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:Lcom/google/android/gms/internal/measurement/i4;

.field public final c:I

.field public final d:I

.field public e:I


# direct methods
.method public constructor <init>(Ljava/util/List;Lcom/google/android/gms/internal/measurement/i4;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp3/k;->a:Ljava/lang/Object;

    .line 5
    .line 6
    iput-object p2, p0, Lp3/k;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    if-eqz p2, :cond_0

    .line 10
    .line 11
    iget-object v1, p2, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v1, Lc2/k;

    .line 14
    .line 15
    iget-object v1, v1, Lc2/k;->f:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v1, Landroid/view/MotionEvent;

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    move-object v1, v0

    .line 21
    :goto_0
    const/4 v2, 0x0

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getClassification()I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    move v1, v2

    .line 30
    :goto_1
    iput v1, p0, Lp3/k;->c:I

    .line 31
    .line 32
    if-eqz p2, :cond_2

    .line 33
    .line 34
    iget-object v1, p2, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v1, Lc2/k;

    .line 37
    .line 38
    iget-object v1, v1, Lc2/k;->f:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v1, Landroid/view/MotionEvent;

    .line 41
    .line 42
    goto :goto_2

    .line 43
    :cond_2
    move-object v1, v0

    .line 44
    :goto_2
    if-eqz v1, :cond_3

    .line 45
    .line 46
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getButtonState()I

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    goto :goto_3

    .line 51
    :cond_3
    move v1, v2

    .line 52
    :goto_3
    iput v1, p0, Lp3/k;->d:I

    .line 53
    .line 54
    if-eqz p2, :cond_4

    .line 55
    .line 56
    iget-object v1, p2, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v1, Lc2/k;

    .line 59
    .line 60
    iget-object v1, v1, Lc2/k;->f:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v1, Landroid/view/MotionEvent;

    .line 63
    .line 64
    goto :goto_4

    .line 65
    :cond_4
    move-object v1, v0

    .line 66
    :goto_4
    if-eqz v1, :cond_5

    .line 67
    .line 68
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getMetaState()I

    .line 69
    .line 70
    .line 71
    :cond_5
    if-eqz p2, :cond_6

    .line 72
    .line 73
    iget-object p2, p2, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast p2, Lc2/k;

    .line 76
    .line 77
    iget-object p2, p2, Lc2/k;->f:Ljava/lang/Object;

    .line 78
    .line 79
    move-object v0, p2

    .line 80
    check-cast v0, Landroid/view/MotionEvent;

    .line 81
    .line 82
    :cond_6
    const/4 p2, 0x3

    .line 83
    const/4 v1, 0x2

    .line 84
    const/4 v3, 0x1

    .line 85
    if-eqz v0, :cond_a

    .line 86
    .line 87
    invoke-virtual {v0}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 88
    .line 89
    .line 90
    move-result p1

    .line 91
    if-eqz p1, :cond_9

    .line 92
    .line 93
    if-eq p1, v3, :cond_8

    .line 94
    .line 95
    if-eq p1, v1, :cond_7

    .line 96
    .line 97
    packed-switch p1, :pswitch_data_0

    .line 98
    .line 99
    .line 100
    goto :goto_8

    .line 101
    :pswitch_0
    const/4 v2, 0x5

    .line 102
    goto :goto_8

    .line 103
    :pswitch_1
    const/4 v2, 0x4

    .line 104
    goto :goto_8

    .line 105
    :pswitch_2
    const/4 v2, 0x6

    .line 106
    goto :goto_8

    .line 107
    :cond_7
    :pswitch_3
    move v2, p2

    .line 108
    goto :goto_8

    .line 109
    :cond_8
    :goto_5
    :pswitch_4
    move v2, v1

    .line 110
    goto :goto_8

    .line 111
    :cond_9
    :goto_6
    :pswitch_5
    move v2, v3

    .line 112
    goto :goto_8

    .line 113
    :cond_a
    move-object v0, p1

    .line 114
    check-cast v0, Ljava/util/Collection;

    .line 115
    .line 116
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 117
    .line 118
    .line 119
    move-result v0

    .line 120
    :goto_7
    if-ge v2, v0, :cond_7

    .line 121
    .line 122
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v4

    .line 126
    check-cast v4, Lp3/t;

    .line 127
    .line 128
    invoke-static {v4}, Lp3/s;->d(Lp3/t;)Z

    .line 129
    .line 130
    .line 131
    move-result v5

    .line 132
    if-eqz v5, :cond_b

    .line 133
    .line 134
    goto :goto_5

    .line 135
    :cond_b
    invoke-static {v4}, Lp3/s;->b(Lp3/t;)Z

    .line 136
    .line 137
    .line 138
    move-result v4

    .line 139
    if-eqz v4, :cond_c

    .line 140
    .line 141
    goto :goto_6

    .line 142
    :cond_c
    add-int/lit8 v2, v2, 0x1

    .line 143
    .line 144
    goto :goto_7

    .line 145
    :goto_8
    iput v2, p0, Lp3/k;->e:I

    .line 146
    .line 147
    return-void

    .line 148
    nop

    .line 149
    :pswitch_data_0
    .packed-switch 0x5
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
