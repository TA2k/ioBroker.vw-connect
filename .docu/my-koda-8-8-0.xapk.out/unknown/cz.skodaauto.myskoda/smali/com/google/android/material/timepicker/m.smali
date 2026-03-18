.class public final Lcom/google/android/material/timepicker/m;
.super Lcom/google/android/material/timepicker/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic e:I

.field public final synthetic f:Lcom/google/android/material/timepicker/n;


# direct methods
.method public constructor <init>(Lcom/google/android/material/timepicker/n;Landroid/content/Context;I)V
    .locals 0

    .line 1
    iput p3, p0, Lcom/google/android/material/timepicker/m;->e:I

    .line 2
    .line 3
    packed-switch p3, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/google/android/material/timepicker/m;->f:Lcom/google/android/material/timepicker/n;

    .line 7
    .line 8
    const p1, 0x7f120717

    .line 9
    .line 10
    .line 11
    invoke-direct {p0, p2, p1}, Lcom/google/android/material/timepicker/a;-><init>(Landroid/content/Context;I)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_0
    iput-object p1, p0, Lcom/google/android/material/timepicker/m;->f:Lcom/google/android/material/timepicker/n;

    .line 16
    .line 17
    const p1, 0x7f120719

    .line 18
    .line 19
    .line 20
    invoke-direct {p0, p2, p1}, Lcom/google/android/material/timepicker/a;-><init>(Landroid/content/Context;I)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final d(Landroid/view/View;Le6/d;)V
    .locals 2

    .line 1
    iget v0, p0, Lcom/google/android/material/timepicker/m;->e:I

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
    invoke-virtual {p1}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    iget-object p0, p0, Lcom/google/android/material/timepicker/m;->f:Lcom/google/android/material/timepicker/n;

    .line 14
    .line 15
    iget-object p0, p0, Lcom/google/android/material/timepicker/n;->e:Lcom/google/android/material/timepicker/l;

    .line 16
    .line 17
    iget p0, p0, Lcom/google/android/material/timepicker/l;->h:I

    .line 18
    .line 19
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    const v0, 0x7f12071a

    .line 28
    .line 29
    .line 30
    invoke-virtual {p1, v0, p0}, Landroid/content/res/Resources;->getString(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {p2, p0}, Le6/d;->j(Ljava/lang/CharSequence;)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :pswitch_0
    invoke-super {p0, p1, p2}, Lcom/google/android/material/timepicker/a;->d(Landroid/view/View;Le6/d;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p1}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    iget-object p0, p0, Lcom/google/android/material/timepicker/m;->f:Lcom/google/android/material/timepicker/n;

    .line 46
    .line 47
    iget-object p0, p0, Lcom/google/android/material/timepicker/n;->e:Lcom/google/android/material/timepicker/l;

    .line 48
    .line 49
    iget v0, p0, Lcom/google/android/material/timepicker/l;->f:I

    .line 50
    .line 51
    const/4 v1, 0x1

    .line 52
    if-ne v0, v1, :cond_0

    .line 53
    .line 54
    const v0, 0x7f120716

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_0
    const v0, 0x7f120718

    .line 59
    .line 60
    .line 61
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/material/timepicker/l;->h()I

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    invoke-virtual {p1, v0, p0}, Landroid/content/res/Resources;->getString(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-virtual {p2, p0}, Le6/d;->j(Ljava/lang/CharSequence;)V

    .line 78
    .line 79
    .line 80
    return-void

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
