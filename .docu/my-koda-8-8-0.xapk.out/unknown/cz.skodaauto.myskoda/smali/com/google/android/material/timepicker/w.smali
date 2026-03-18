.class public final Lcom/google/android/material/timepicker/w;
.super Landroid/view/GestureDetector$SimpleOnGestureListener;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:Lcom/google/android/material/timepicker/TimePickerView;


# direct methods
.method public constructor <init>(Lcom/google/android/material/timepicker/TimePickerView;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/material/timepicker/w;->d:Lcom/google/android/material/timepicker/TimePickerView;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/view/GestureDetector$SimpleOnGestureListener;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final onDoubleTap(Landroid/view/MotionEvent;)Z
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/android/material/timepicker/w;->d:Lcom/google/android/material/timepicker/TimePickerView;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/android/material/timepicker/TimePickerView;->k:Lcom/google/android/material/timepicker/i;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    iput p1, p0, Lcom/google/android/material/timepicker/i;->M:I

    .line 9
    .line 10
    iget-object v0, p0, Lcom/google/android/material/timepicker/i;->K:Lcom/google/android/material/button/MaterialButton;

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Lcom/google/android/material/timepicker/i;->l(Lcom/google/android/material/button/MaterialButton;)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lcom/google/android/material/timepicker/i;->A:Lcom/google/android/material/timepicker/t;

    .line 16
    .line 17
    invoke-virtual {p0}, Lcom/google/android/material/timepicker/t;->d()V

    .line 18
    .line 19
    .line 20
    return p1

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return p0
.end method
