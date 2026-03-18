.class public final Lcom/google/android/material/timepicker/r;
.super Lcom/google/android/material/timepicker/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic e:I

.field public final synthetic f:Landroid/content/res/Resources;

.field public final synthetic g:Lcom/google/android/material/timepicker/l;


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/content/res/Resources;Lcom/google/android/material/timepicker/l;I)V
    .locals 0

    .line 1
    iput p4, p0, Lcom/google/android/material/timepicker/r;->e:I

    .line 2
    .line 3
    packed-switch p4, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/android/material/timepicker/r;->f:Landroid/content/res/Resources;

    .line 7
    .line 8
    iput-object p3, p0, Lcom/google/android/material/timepicker/r;->g:Lcom/google/android/material/timepicker/l;

    .line 9
    .line 10
    const p2, 0x7f120717

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, p1, p2}, Lcom/google/android/material/timepicker/a;-><init>(Landroid/content/Context;I)V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :pswitch_0
    iput-object p2, p0, Lcom/google/android/material/timepicker/r;->f:Landroid/content/res/Resources;

    .line 18
    .line 19
    iput-object p3, p0, Lcom/google/android/material/timepicker/r;->g:Lcom/google/android/material/timepicker/l;

    .line 20
    .line 21
    const p2, 0x7f120719

    .line 22
    .line 23
    .line 24
    invoke-direct {p0, p1, p2}, Lcom/google/android/material/timepicker/a;-><init>(Landroid/content/Context;I)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final d(Landroid/view/View;Le6/d;)V
    .locals 3

    .line 1
    iget v0, p0, Lcom/google/android/material/timepicker/r;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2}, Lcom/google/android/material/timepicker/a;->d(Landroid/view/View;Le6/d;)V

    .line 7
    .line 8
    .line 9
    new-instance v0, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 12
    .line 13
    .line 14
    iget-object v1, p0, Lcom/google/android/material/timepicker/r;->f:Landroid/content/res/Resources;

    .line 15
    .line 16
    const v2, 0x7f120726

    .line 17
    .line 18
    .line 19
    invoke-virtual {v1, v2}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    const-string v1, " "

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    iget-object p0, p0, Lcom/google/android/material/timepicker/r;->g:Lcom/google/android/material/timepicker/l;

    .line 36
    .line 37
    iget p0, p0, Lcom/google/android/material/timepicker/l;->h:I

    .line 38
    .line 39
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    const v1, 0x7f12071a

    .line 48
    .line 49
    .line 50
    invoke-virtual {p1, v1, p0}, Landroid/content/res/Resources;->getString(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-virtual {p2, p0}, Le6/d;->j(Ljava/lang/CharSequence;)V

    .line 62
    .line 63
    .line 64
    return-void

    .line 65
    :pswitch_0
    invoke-super {p0, p1, p2}, Lcom/google/android/material/timepicker/a;->d(Landroid/view/View;Le6/d;)V

    .line 66
    .line 67
    .line 68
    new-instance v0, Ljava/lang/StringBuilder;

    .line 69
    .line 70
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 71
    .line 72
    .line 73
    iget-object v1, p0, Lcom/google/android/material/timepicker/r;->f:Landroid/content/res/Resources;

    .line 74
    .line 75
    const v2, 0x7f120725

    .line 76
    .line 77
    .line 78
    invoke-virtual {v1, v2}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    const-string v1, " "

    .line 86
    .line 87
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {p1}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    iget-object p0, p0, Lcom/google/android/material/timepicker/r;->g:Lcom/google/android/material/timepicker/l;

    .line 95
    .line 96
    iget v1, p0, Lcom/google/android/material/timepicker/l;->f:I

    .line 97
    .line 98
    const/4 v2, 0x1

    .line 99
    if-ne v1, v2, :cond_0

    .line 100
    .line 101
    const v1, 0x7f120716

    .line 102
    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_0
    const v1, 0x7f120718

    .line 106
    .line 107
    .line 108
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/material/timepicker/l;->h()I

    .line 109
    .line 110
    .line 111
    move-result p0

    .line 112
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    invoke-virtual {p1, v1, p0}, Landroid/content/res/Resources;->getString(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    invoke-virtual {p2, p0}, Le6/d;->j(Ljava/lang/CharSequence;)V

    .line 132
    .line 133
    .line 134
    return-void

    .line 135
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
