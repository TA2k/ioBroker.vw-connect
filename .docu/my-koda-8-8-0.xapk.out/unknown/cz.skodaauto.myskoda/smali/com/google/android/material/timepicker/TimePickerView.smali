.class Lcom/google/android/material/timepicker/TimePickerView;
.super Landroidx/constraintlayout/widget/ConstraintLayout;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic l:I


# instance fields
.field public final d:Lcom/google/android/material/chip/Chip;

.field public final e:Lcom/google/android/material/chip/Chip;

.field public final f:Lcom/google/android/material/timepicker/ClockHandView;

.field public final g:Lcom/google/android/material/timepicker/ClockFaceView;

.field public final h:Lcom/google/android/material/button/MaterialButtonToggleGroup;

.field public i:Lcom/google/android/material/timepicker/n;

.field public j:Lcom/google/android/material/timepicker/n;

.field public k:Lcom/google/android/material/timepicker/i;


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, p2, v0}, Landroidx/constraintlayout/widget/ConstraintLayout;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 3
    .line 4
    .line 5
    new-instance p2, Lcom/google/android/material/timepicker/v;

    .line 6
    .line 7
    invoke-direct {p2, p0, v0}, Lcom/google/android/material/timepicker/v;-><init>(Ljava/lang/Object;I)V

    .line 8
    .line 9
    .line 10
    invoke-static {p1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    const v0, 0x7f0d02a1

    .line 15
    .line 16
    .line 17
    invoke-virtual {p1, v0, p0}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    .line 18
    .line 19
    .line 20
    const p1, 0x7f0a01bb

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, p1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    check-cast p1, Lcom/google/android/material/timepicker/ClockFaceView;

    .line 28
    .line 29
    iput-object p1, p0, Lcom/google/android/material/timepicker/TimePickerView;->g:Lcom/google/android/material/timepicker/ClockFaceView;

    .line 30
    .line 31
    const p1, 0x7f0a01c0

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, p1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    check-cast p1, Lcom/google/android/material/button/MaterialButtonToggleGroup;

    .line 39
    .line 40
    iput-object p1, p0, Lcom/google/android/material/timepicker/TimePickerView;->h:Lcom/google/android/material/button/MaterialButtonToggleGroup;

    .line 41
    .line 42
    new-instance v0, Lcom/google/android/material/timepicker/u;

    .line 43
    .line 44
    const/4 v1, 0x0

    .line 45
    invoke-direct {v0, p0, v1}, Lcom/google/android/material/timepicker/u;-><init>(Ljava/lang/Object;I)V

    .line 46
    .line 47
    .line 48
    iget-object p1, p1, Lcom/google/android/material/button/MaterialButtonToggleGroup;->n:Ljava/util/LinkedHashSet;

    .line 49
    .line 50
    invoke-virtual {p1, v0}, Ljava/util/AbstractCollection;->add(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    const p1, 0x7f0a01c5

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0, p1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    check-cast p1, Lcom/google/android/material/chip/Chip;

    .line 61
    .line 62
    iput-object p1, p0, Lcom/google/android/material/timepicker/TimePickerView;->d:Lcom/google/android/material/chip/Chip;

    .line 63
    .line 64
    const v0, 0x7f0a01c2

    .line 65
    .line 66
    .line 67
    invoke-virtual {p0, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    check-cast v0, Lcom/google/android/material/chip/Chip;

    .line 72
    .line 73
    iput-object v0, p0, Lcom/google/android/material/timepicker/TimePickerView;->e:Lcom/google/android/material/chip/Chip;

    .line 74
    .line 75
    const v1, 0x7f0a01bc

    .line 76
    .line 77
    .line 78
    invoke-virtual {p0, v1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    check-cast v1, Lcom/google/android/material/timepicker/ClockHandView;

    .line 83
    .line 84
    iput-object v1, p0, Lcom/google/android/material/timepicker/TimePickerView;->f:Lcom/google/android/material/timepicker/ClockHandView;

    .line 85
    .line 86
    new-instance v1, Landroid/view/GestureDetector;

    .line 87
    .line 88
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    new-instance v3, Lcom/google/android/material/timepicker/w;

    .line 93
    .line 94
    invoke-direct {v3, p0}, Lcom/google/android/material/timepicker/w;-><init>(Lcom/google/android/material/timepicker/TimePickerView;)V

    .line 95
    .line 96
    .line 97
    invoke-direct {v1, v2, v3}, Landroid/view/GestureDetector;-><init>(Landroid/content/Context;Landroid/view/GestureDetector$OnGestureListener;)V

    .line 98
    .line 99
    .line 100
    new-instance p0, Lcom/google/android/material/timepicker/x;

    .line 101
    .line 102
    invoke-direct {p0, v1}, Lcom/google/android/material/timepicker/x;-><init>(Landroid/view/GestureDetector;)V

    .line 103
    .line 104
    .line 105
    invoke-virtual {p1, p0}, Landroid/view/View;->setOnTouchListener(Landroid/view/View$OnTouchListener;)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v0, p0}, Landroid/view/View;->setOnTouchListener(Landroid/view/View$OnTouchListener;)V

    .line 109
    .line 110
    .line 111
    const/16 p0, 0xc

    .line 112
    .line 113
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    const v1, 0x7f0a0290

    .line 118
    .line 119
    .line 120
    invoke-virtual {p1, v1, p0}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    const/16 p0, 0xa

    .line 124
    .line 125
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    invoke-virtual {v0, v1, p0}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {p1, p2}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v0, p2}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 136
    .line 137
    .line 138
    const-string p0, "android.view.View"

    .line 139
    .line 140
    invoke-virtual {p1, p0}, Lcom/google/android/material/chip/Chip;->setAccessibilityClassName(Ljava/lang/CharSequence;)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v0, p0}, Lcom/google/android/material/chip/Chip;->setAccessibilityClassName(Ljava/lang/CharSequence;)V

    .line 144
    .line 145
    .line 146
    return-void
.end method


# virtual methods
.method public final onVisibilityChanged(Landroid/view/View;I)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2}, Landroid/view/View;->onVisibilityChanged(Landroid/view/View;I)V

    .line 2
    .line 3
    .line 4
    if-ne p1, p0, :cond_0

    .line 5
    .line 6
    if-nez p2, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, Lcom/google/android/material/timepicker/TimePickerView;->e:Lcom/google/android/material/chip/Chip;

    .line 9
    .line 10
    const/16 p1, 0x8

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Landroid/view/View;->sendAccessibilityEvent(I)V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void
.end method
