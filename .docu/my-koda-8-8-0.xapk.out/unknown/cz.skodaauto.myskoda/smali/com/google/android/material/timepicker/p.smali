.class public final Lcom/google/android/material/timepicker/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/widget/TextView$OnEditorActionListener;
.implements Landroid/view/View$OnKeyListener;


# instance fields
.field public final d:Lcom/google/android/material/timepicker/ChipTextInputComboView;

.field public final e:Lcom/google/android/material/timepicker/ChipTextInputComboView;

.field public final f:Lcom/google/android/material/timepicker/l;

.field public g:Z


# direct methods
.method public constructor <init>(Lcom/google/android/material/timepicker/ChipTextInputComboView;Lcom/google/android/material/timepicker/ChipTextInputComboView;Lcom/google/android/material/timepicker/l;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Lcom/google/android/material/timepicker/p;->g:Z

    .line 6
    .line 7
    iput-object p1, p0, Lcom/google/android/material/timepicker/p;->d:Lcom/google/android/material/timepicker/ChipTextInputComboView;

    .line 8
    .line 9
    iput-object p2, p0, Lcom/google/android/material/timepicker/p;->e:Lcom/google/android/material/timepicker/ChipTextInputComboView;

    .line 10
    .line 11
    iput-object p3, p0, Lcom/google/android/material/timepicker/p;->f:Lcom/google/android/material/timepicker/l;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a(I)V
    .locals 4

    .line 1
    const/16 v0, 0xc

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-ne p1, v0, :cond_0

    .line 6
    .line 7
    move v0, v2

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v0, v1

    .line 10
    :goto_0
    iget-object v3, p0, Lcom/google/android/material/timepicker/p;->e:Lcom/google/android/material/timepicker/ChipTextInputComboView;

    .line 11
    .line 12
    invoke-virtual {v3, v0}, Lcom/google/android/material/timepicker/ChipTextInputComboView;->setChecked(Z)V

    .line 13
    .line 14
    .line 15
    const/16 v0, 0xa

    .line 16
    .line 17
    if-ne p1, v0, :cond_1

    .line 18
    .line 19
    move v1, v2

    .line 20
    :cond_1
    iget-object v0, p0, Lcom/google/android/material/timepicker/p;->d:Lcom/google/android/material/timepicker/ChipTextInputComboView;

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Lcom/google/android/material/timepicker/ChipTextInputComboView;->setChecked(Z)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lcom/google/android/material/timepicker/p;->f:Lcom/google/android/material/timepicker/l;

    .line 26
    .line 27
    iput p1, p0, Lcom/google/android/material/timepicker/l;->i:I

    .line 28
    .line 29
    return-void
.end method

.method public final onEditorAction(Landroid/widget/TextView;ILandroid/view/KeyEvent;)Z
    .locals 0

    .line 1
    const/4 p1, 0x5

    .line 2
    if-ne p2, p1, :cond_0

    .line 3
    .line 4
    const/4 p1, 0x1

    .line 5
    goto :goto_0

    .line 6
    :cond_0
    const/4 p1, 0x0

    .line 7
    :goto_0
    if-eqz p1, :cond_1

    .line 8
    .line 9
    const/16 p2, 0xc

    .line 10
    .line 11
    invoke-virtual {p0, p2}, Lcom/google/android/material/timepicker/p;->a(I)V

    .line 12
    .line 13
    .line 14
    :cond_1
    return p1
.end method

.method public final onKey(Landroid/view/View;ILandroid/view/KeyEvent;)Z
    .locals 7

    .line 1
    iget-boolean v0, p0, Lcom/google/android/material/timepicker/p;->g:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    const/4 v0, 0x1

    .line 8
    iput-boolean v0, p0, Lcom/google/android/material/timepicker/p;->g:Z

    .line 9
    .line 10
    check-cast p1, Landroid/widget/EditText;

    .line 11
    .line 12
    iget-object v2, p0, Lcom/google/android/material/timepicker/p;->f:Lcom/google/android/material/timepicker/l;

    .line 13
    .line 14
    iget v2, v2, Lcom/google/android/material/timepicker/l;->i:I

    .line 15
    .line 16
    const/4 v3, 0x2

    .line 17
    const/16 v4, 0x10

    .line 18
    .line 19
    const/4 v5, 0x7

    .line 20
    const/16 v6, 0xc

    .line 21
    .line 22
    if-ne v2, v6, :cond_3

    .line 23
    .line 24
    const/16 v2, 0x43

    .line 25
    .line 26
    if-ne p2, v2, :cond_1

    .line 27
    .line 28
    invoke-virtual {p3}, Landroid/view/KeyEvent;->getAction()I

    .line 29
    .line 30
    .line 31
    move-result p3

    .line 32
    if-nez p3, :cond_1

    .line 33
    .line 34
    invoke-virtual {p1}, Landroid/widget/EditText;->getText()Landroid/text/Editable;

    .line 35
    .line 36
    .line 37
    move-result-object p3

    .line 38
    invoke-static {p3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 39
    .line 40
    .line 41
    move-result p3

    .line 42
    if-eqz p3, :cond_1

    .line 43
    .line 44
    const/16 p1, 0xa

    .line 45
    .line 46
    invoke-virtual {p0, p1}, Lcom/google/android/material/timepicker/p;->a(I)V

    .line 47
    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    if-lt p2, v5, :cond_2

    .line 51
    .line 52
    if-gt p2, v4, :cond_2

    .line 53
    .line 54
    invoke-virtual {p1}, Landroid/widget/TextView;->getSelectionStart()I

    .line 55
    .line 56
    .line 57
    move-result p2

    .line 58
    if-nez p2, :cond_2

    .line 59
    .line 60
    invoke-virtual {p1}, Landroid/widget/TextView;->length()I

    .line 61
    .line 62
    .line 63
    move-result p2

    .line 64
    if-ne p2, v3, :cond_2

    .line 65
    .line 66
    invoke-virtual {p1}, Landroid/widget/EditText;->getText()Landroid/text/Editable;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    invoke-interface {p1}, Landroid/text/Editable;->clear()V

    .line 71
    .line 72
    .line 73
    :cond_2
    :goto_0
    move v0, v1

    .line 74
    goto :goto_1

    .line 75
    :cond_3
    invoke-virtual {p1}, Landroid/widget/EditText;->getText()Landroid/text/Editable;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    if-nez v2, :cond_4

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_4
    if-lt p2, v5, :cond_5

    .line 83
    .line 84
    if-gt p2, v4, :cond_5

    .line 85
    .line 86
    invoke-virtual {p3}, Landroid/view/KeyEvent;->getAction()I

    .line 87
    .line 88
    .line 89
    move-result p3

    .line 90
    if-ne p3, v0, :cond_5

    .line 91
    .line 92
    invoke-virtual {p1}, Landroid/widget/TextView;->getSelectionStart()I

    .line 93
    .line 94
    .line 95
    move-result p3

    .line 96
    if-ne p3, v3, :cond_5

    .line 97
    .line 98
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 99
    .line 100
    .line 101
    move-result p3

    .line 102
    if-ne p3, v3, :cond_5

    .line 103
    .line 104
    invoke-virtual {p0, v6}, Lcom/google/android/material/timepicker/p;->a(I)V

    .line 105
    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_5
    if-lt p2, v5, :cond_2

    .line 109
    .line 110
    if-gt p2, v4, :cond_2

    .line 111
    .line 112
    invoke-virtual {p1}, Landroid/widget/TextView;->getSelectionStart()I

    .line 113
    .line 114
    .line 115
    move-result p2

    .line 116
    if-nez p2, :cond_2

    .line 117
    .line 118
    invoke-virtual {p1}, Landroid/widget/TextView;->length()I

    .line 119
    .line 120
    .line 121
    move-result p2

    .line 122
    if-ne p2, v3, :cond_2

    .line 123
    .line 124
    invoke-virtual {p1}, Landroid/widget/EditText;->getText()Landroid/text/Editable;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    invoke-interface {p1}, Landroid/text/Editable;->clear()V

    .line 129
    .line 130
    .line 131
    goto :goto_0

    .line 132
    :goto_1
    iput-boolean v1, p0, Lcom/google/android/material/timepicker/p;->g:Z

    .line 133
    .line 134
    return v0
.end method
