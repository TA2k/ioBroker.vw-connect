.class public final synthetic Lcom/google/android/material/timepicker/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcom/google/android/material/timepicker/u;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lcom/google/android/material/timepicker/u;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(IZ)V
    .locals 4

    .line 1
    iget v0, p0, Lcom/google/android/material/timepicker/u;->a:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    const v3, 0x7f0a01bf

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lcom/google/android/material/timepicker/u;->b:Ljava/lang/Object;

    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    check-cast p0, Lcom/google/android/material/timepicker/t;

    .line 14
    .line 15
    if-nez p2, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    if-ne p1, v3, :cond_1

    .line 19
    .line 20
    move v1, v2

    .line 21
    :cond_1
    iget-object p0, p0, Lcom/google/android/material/timepicker/t;->e:Lcom/google/android/material/timepicker/l;

    .line 22
    .line 23
    invoke-virtual {p0, v1}, Lcom/google/android/material/timepicker/l;->k(I)V

    .line 24
    .line 25
    .line 26
    :goto_0
    return-void

    .line 27
    :pswitch_0
    check-cast p0, Lcom/google/android/material/timepicker/TimePickerView;

    .line 28
    .line 29
    if-nez p2, :cond_2

    .line 30
    .line 31
    sget p0, Lcom/google/android/material/timepicker/TimePickerView;->l:I

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_2
    iget-object p0, p0, Lcom/google/android/material/timepicker/TimePickerView;->i:Lcom/google/android/material/timepicker/n;

    .line 35
    .line 36
    if-eqz p0, :cond_4

    .line 37
    .line 38
    if-ne p1, v3, :cond_3

    .line 39
    .line 40
    move v1, v2

    .line 41
    :cond_3
    iget-object p0, p0, Lcom/google/android/material/timepicker/n;->e:Lcom/google/android/material/timepicker/l;

    .line 42
    .line 43
    invoke-virtual {p0, v1}, Lcom/google/android/material/timepicker/l;->k(I)V

    .line 44
    .line 45
    .line 46
    :cond_4
    :goto_1
    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
