.class public final synthetic Ld4/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Comparator;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Ld4/a0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ld4/a0;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 5

    .line 1
    iget v0, p0, Ld4/a0;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Ld4/a0;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, [Lay0/k;

    .line 9
    .line 10
    array-length v0, p0

    .line 11
    const/4 v1, 0x0

    .line 12
    move v2, v1

    .line 13
    :goto_0
    if-ge v2, v0, :cond_1

    .line 14
    .line 15
    aget-object v3, p0, v2

    .line 16
    .line 17
    invoke-interface {v3, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    check-cast v4, Ljava/lang/Comparable;

    .line 22
    .line 23
    invoke-interface {v3, p2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    check-cast v3, Ljava/lang/Comparable;

    .line 28
    .line 29
    invoke-static {v4, v3}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-eqz v3, :cond_0

    .line 34
    .line 35
    move v1, v3

    .line 36
    goto :goto_1

    .line 37
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    :goto_1
    return v1

    .line 41
    :pswitch_0
    check-cast p0, La8/t1;

    .line 42
    .line 43
    check-cast p1, Lh0/i;

    .line 44
    .line 45
    check-cast p2, Lh0/i;

    .line 46
    .line 47
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    iget-object p0, p1, Lh0/i;->a:Lh0/t0;

    .line 51
    .line 52
    iget-object p0, p0, Lh0/t0;->j:Ljava/lang/Class;

    .line 53
    .line 54
    const/4 p1, 0x0

    .line 55
    const/4 v0, 0x1

    .line 56
    const-class v1, Lt0/e;

    .line 57
    .line 58
    const-class v2, Lb0/k1;

    .line 59
    .line 60
    const/4 v3, 0x2

    .line 61
    const-class v4, Landroid/media/MediaCodec;

    .line 62
    .line 63
    if-ne p0, v4, :cond_2

    .line 64
    .line 65
    move p0, v3

    .line 66
    goto :goto_3

    .line 67
    :cond_2
    if-eq p0, v2, :cond_4

    .line 68
    .line 69
    if-ne p0, v1, :cond_3

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_3
    move p0, v0

    .line 73
    goto :goto_3

    .line 74
    :cond_4
    :goto_2
    move p0, p1

    .line 75
    :goto_3
    iget-object p2, p2, Lh0/i;->a:Lh0/t0;

    .line 76
    .line 77
    iget-object p2, p2, Lh0/t0;->j:Ljava/lang/Class;

    .line 78
    .line 79
    if-ne p2, v4, :cond_5

    .line 80
    .line 81
    move p1, v3

    .line 82
    goto :goto_4

    .line 83
    :cond_5
    if-eq p2, v2, :cond_7

    .line 84
    .line 85
    if-ne p2, v1, :cond_6

    .line 86
    .line 87
    goto :goto_4

    .line 88
    :cond_6
    move p1, v0

    .line 89
    :cond_7
    :goto_4
    sub-int/2addr p0, p1

    .line 90
    return p0

    .line 91
    :pswitch_1
    check-cast p0, Lcom/google/android/material/button/MaterialButtonToggleGroup;

    .line 92
    .line 93
    check-cast p1, Lcom/google/android/material/button/MaterialButton;

    .line 94
    .line 95
    check-cast p2, Lcom/google/android/material/button/MaterialButton;

    .line 96
    .line 97
    iget-boolean v0, p1, Lcom/google/android/material/button/MaterialButton;->r:Z

    .line 98
    .line 99
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    iget-boolean v1, p2, Lcom/google/android/material/button/MaterialButton;->r:Z

    .line 104
    .line 105
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    invoke-virtual {v0, v1}, Ljava/lang/Boolean;->compareTo(Ljava/lang/Boolean;)I

    .line 110
    .line 111
    .line 112
    move-result v0

    .line 113
    if-eqz v0, :cond_8

    .line 114
    .line 115
    goto :goto_5

    .line 116
    :cond_8
    invoke-virtual {p1}, Landroid/view/View;->isPressed()Z

    .line 117
    .line 118
    .line 119
    move-result v0

    .line 120
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    invoke-virtual {p2}, Landroid/view/View;->isPressed()Z

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    invoke-virtual {v0, v1}, Ljava/lang/Boolean;->compareTo(Ljava/lang/Boolean;)I

    .line 133
    .line 134
    .line 135
    move-result v0

    .line 136
    if-eqz v0, :cond_9

    .line 137
    .line 138
    goto :goto_5

    .line 139
    :cond_9
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->indexOfChild(Landroid/view/View;)I

    .line 140
    .line 141
    .line 142
    move-result p1

    .line 143
    invoke-virtual {p0, p2}, Landroid/view/ViewGroup;->indexOfChild(Landroid/view/View;)I

    .line 144
    .line 145
    .line 146
    move-result p0

    .line 147
    invoke-static {p1, p0}, Ljava/lang/Integer;->compare(II)I

    .line 148
    .line 149
    .line 150
    move-result v0

    .line 151
    :goto_5
    return v0

    .line 152
    :pswitch_2
    check-cast p0, Lf8/v;

    .line 153
    .line 154
    invoke-interface {p0, p2}, Lf8/v;->b(Ljava/lang/Object;)I

    .line 155
    .line 156
    .line 157
    move-result p2

    .line 158
    invoke-interface {p0, p1}, Lf8/v;->b(Ljava/lang/Object;)I

    .line 159
    .line 160
    .line 161
    move-result p0

    .line 162
    sub-int/2addr p2, p0

    .line 163
    return p2

    .line 164
    :pswitch_3
    check-cast p0, Ldl0/k;

    .line 165
    .line 166
    invoke-virtual {p0, p1, p2}, Ldl0/k;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object p0

    .line 170
    check-cast p0, Ljava/lang/Number;

    .line 171
    .line 172
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 173
    .line 174
    .line 175
    move-result p0

    .line 176
    return p0

    .line 177
    :pswitch_4
    check-cast p0, Lay0/n;

    .line 178
    .line 179
    invoke-interface {p0, p1, p2}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object p0

    .line 183
    check-cast p0, Ljava/lang/Number;

    .line 184
    .line 185
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 186
    .line 187
    .line 188
    move-result p0

    .line 189
    return p0

    .line 190
    nop

    .line 191
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
