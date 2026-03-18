.class public final Lcom/google/android/material/timepicker/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnClickListener;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lcom/google/android/material/timepicker/i;


# direct methods
.method public synthetic constructor <init>(Lcom/google/android/material/timepicker/i;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcom/google/android/material/timepicker/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcom/google/android/material/timepicker/h;->e:Lcom/google/android/material/timepicker/i;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onClick(Landroid/view/View;)V
    .locals 2

    .line 1
    iget v0, p0, Lcom/google/android/material/timepicker/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/android/material/timepicker/h;->e:Lcom/google/android/material/timepicker/i;

    .line 7
    .line 8
    iget p1, p0, Lcom/google/android/material/timepicker/i;->M:I

    .line 9
    .line 10
    if-nez p1, :cond_0

    .line 11
    .line 12
    const/4 p1, 0x1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p1, 0x0

    .line 15
    :goto_0
    iput p1, p0, Lcom/google/android/material/timepicker/i;->M:I

    .line 16
    .line 17
    iget-object p1, p0, Lcom/google/android/material/timepicker/i;->K:Lcom/google/android/material/button/MaterialButton;

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Lcom/google/android/material/timepicker/i;->l(Lcom/google/android/material/button/MaterialButton;)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :pswitch_0
    iget-object p0, p0, Lcom/google/android/material/timepicker/h;->e:Lcom/google/android/material/timepicker/i;

    .line 24
    .line 25
    iget-object v0, p0, Lcom/google/android/material/timepicker/i;->u:Ljava/util/LinkedHashSet;

    .line 26
    .line 27
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_1

    .line 36
    .line 37
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    check-cast v1, Landroid/view/View$OnClickListener;

    .line 42
    .line 43
    invoke-interface {v1, p1}, Landroid/view/View$OnClickListener;->onClick(Landroid/view/View;)V

    .line 44
    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_1
    const/4 p1, 0x0

    .line 48
    invoke-virtual {p0, p1, p1}, Landroidx/fragment/app/x;->i(ZZ)V

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    :pswitch_1
    iget-object p0, p0, Lcom/google/android/material/timepicker/h;->e:Lcom/google/android/material/timepicker/i;

    .line 53
    .line 54
    iget-object v0, p0, Lcom/google/android/material/timepicker/i;->t:Ljava/util/LinkedHashSet;

    .line 55
    .line 56
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_2

    .line 65
    .line 66
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    check-cast v1, Landroid/view/View$OnClickListener;

    .line 71
    .line 72
    invoke-interface {v1, p1}, Landroid/view/View$OnClickListener;->onClick(Landroid/view/View;)V

    .line 73
    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_2
    const/4 p1, 0x0

    .line 77
    invoke-virtual {p0, p1, p1}, Landroidx/fragment/app/x;->i(ZZ)V

    .line 78
    .line 79
    .line 80
    return-void

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
