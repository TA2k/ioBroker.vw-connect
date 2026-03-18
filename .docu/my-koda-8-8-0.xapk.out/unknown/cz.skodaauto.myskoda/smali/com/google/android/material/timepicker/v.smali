.class public final Lcom/google/android/material/timepicker/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnClickListener;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcom/google/android/material/timepicker/v;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcom/google/android/material/timepicker/v;->e:Ljava/lang/Object;

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
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/material/timepicker/v;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/android/material/timepicker/v;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lcom/google/android/material/timepicker/t;

    .line 9
    .line 10
    const v0, 0x7f0a0290

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1, v0}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    check-cast p1, Ljava/lang/Integer;

    .line 18
    .line 19
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    invoke-virtual {p0, p1}, Lcom/google/android/material/timepicker/t;->a(I)V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :pswitch_0
    iget-object p0, p0, Lcom/google/android/material/timepicker/v;->e:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p0, Lcom/google/android/material/timepicker/TimePickerView;

    .line 30
    .line 31
    iget-object p0, p0, Lcom/google/android/material/timepicker/TimePickerView;->j:Lcom/google/android/material/timepicker/n;

    .line 32
    .line 33
    if-eqz p0, :cond_0

    .line 34
    .line 35
    const v0, 0x7f0a0290

    .line 36
    .line 37
    .line 38
    invoke-virtual {p1, v0}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    check-cast p1, Ljava/lang/Integer;

    .line 43
    .line 44
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    const/4 v0, 0x1

    .line 49
    invoke-virtual {p0, p1, v0}, Lcom/google/android/material/timepicker/n;->d(IZ)V

    .line 50
    .line 51
    .line 52
    :cond_0
    return-void

    .line 53
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
