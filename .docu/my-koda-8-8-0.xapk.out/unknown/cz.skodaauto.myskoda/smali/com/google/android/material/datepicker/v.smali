.class public final synthetic Lcom/google/android/material/datepicker/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnClickListener;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lcom/google/android/material/datepicker/z;


# direct methods
.method public synthetic constructor <init>(Lcom/google/android/material/datepicker/z;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcom/google/android/material/datepicker/v;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcom/google/android/material/datepicker/v;->e:Lcom/google/android/material/datepicker/z;

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
    .locals 3

    .line 1
    iget v0, p0, Lcom/google/android/material/datepicker/v;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/android/material/datepicker/v;->e:Lcom/google/android/material/datepicker/z;

    .line 7
    .line 8
    iget-object p1, p0, Lcom/google/android/material/datepicker/z;->S:Landroid/widget/Button;

    .line 9
    .line 10
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/z;->l()Lcom/google/android/material/datepicker/i;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-interface {v0}, Lcom/google/android/material/datepicker/i;->k0()Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    invoke-virtual {p1, v0}, Landroid/view/View;->setEnabled(Z)V

    .line 19
    .line 20
    .line 21
    iget-object p1, p0, Lcom/google/android/material/datepicker/z;->Q:Lcom/google/android/material/internal/CheckableImageButton;

    .line 22
    .line 23
    invoke-virtual {p1}, Lcom/google/android/material/internal/CheckableImageButton;->toggle()V

    .line 24
    .line 25
    .line 26
    iget p1, p0, Lcom/google/android/material/datepicker/z;->F:I

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    if-ne p1, v0, :cond_0

    .line 30
    .line 31
    const/4 v0, 0x0

    .line 32
    :cond_0
    iput v0, p0, Lcom/google/android/material/datepicker/z;->F:I

    .line 33
    .line 34
    iget-object p1, p0, Lcom/google/android/material/datepicker/z;->Q:Lcom/google/android/material/internal/CheckableImageButton;

    .line 35
    .line 36
    invoke-virtual {p0, p1}, Lcom/google/android/material/datepicker/z;->p(Lcom/google/android/material/internal/CheckableImageButton;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/z;->o()V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :pswitch_0
    iget-object p0, p0, Lcom/google/android/material/datepicker/v;->e:Lcom/google/android/material/datepicker/z;

    .line 44
    .line 45
    iget-object v0, p0, Lcom/google/android/material/datepicker/z;->u:Ljava/util/LinkedHashSet;

    .line 46
    .line 47
    invoke-virtual {v0}, Ljava/util/AbstractCollection;->iterator()Ljava/util/Iterator;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    if-eqz v1, :cond_1

    .line 56
    .line 57
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    check-cast v1, Landroid/view/View$OnClickListener;

    .line 62
    .line 63
    invoke-interface {v1, p1}, Landroid/view/View$OnClickListener;->onClick(Landroid/view/View;)V

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_1
    const/4 p1, 0x0

    .line 68
    invoke-virtual {p0, p1, p1}, Landroidx/fragment/app/x;->i(ZZ)V

    .line 69
    .line 70
    .line 71
    return-void

    .line 72
    :pswitch_1
    iget-object p0, p0, Lcom/google/android/material/datepicker/v;->e:Lcom/google/android/material/datepicker/z;

    .line 73
    .line 74
    iget-object p1, p0, Lcom/google/android/material/datepicker/z;->t:Ljava/util/LinkedHashSet;

    .line 75
    .line 76
    invoke-virtual {p1}, Ljava/util/AbstractCollection;->iterator()Ljava/util/Iterator;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    if-eqz v0, :cond_2

    .line 85
    .line 86
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    check-cast v0, Lxf0/k0;

    .line 91
    .line 92
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/z;->l()Lcom/google/android/material/datepicker/i;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    invoke-interface {v1}, Lcom/google/android/material/datepicker/i;->n0()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    iget v2, v0, Lxf0/k0;->a:I

    .line 101
    .line 102
    iget-object v0, v0, Lxf0/k0;->b:Lay0/k;

    .line 103
    .line 104
    packed-switch v2, :pswitch_data_1

    .line 105
    .line 106
    .line 107
    check-cast v0, Lxc/b;

    .line 108
    .line 109
    invoke-virtual {v0, v1}, Lxc/b;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    goto :goto_1

    .line 113
    :pswitch_2
    check-cast v0, Lv2/k;

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Lv2/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    goto :goto_1

    .line 119
    :pswitch_3
    check-cast v0, Lc1/l1;

    .line 120
    .line 121
    invoke-virtual {v0, v1}, Lc1/l1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    goto :goto_1

    .line 125
    :cond_2
    const/4 p1, 0x0

    .line 126
    invoke-virtual {p0, p1, p1}, Landroidx/fragment/app/x;->i(ZZ)V

    .line 127
    .line 128
    .line 129
    return-void

    .line 130
    nop

    .line 131
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 132
    .line 133
    .line 134
    .line 135
    .line 136
    .line 137
    .line 138
    .line 139
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
    .end packed-switch
.end method
