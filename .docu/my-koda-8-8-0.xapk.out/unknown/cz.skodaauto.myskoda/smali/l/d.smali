.class public final Ll/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Ll/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ll/d;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onGlobalLayout()V
    .locals 4

    .line 1
    iget v0, p0, Ll/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ll/d;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lm/m0;

    .line 9
    .line 10
    iget-object v0, p0, Lm/m0;->H:Lm/p0;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    iget-object v1, p0, Lm/m0;->F:Landroid/graphics/Rect;

    .line 22
    .line 23
    invoke-virtual {v0, v1}, Landroid/view/View;->getGlobalVisibleRect(Landroid/graphics/Rect;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    invoke-virtual {p0}, Lm/m0;->s()V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0}, Lm/z1;->b()V

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    invoke-virtual {p0}, Lm/z1;->dismiss()V

    .line 37
    .line 38
    .line 39
    :goto_0
    return-void

    .line 40
    :pswitch_0
    iget-object v0, p0, Ll/d;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v0, Lm/p0;

    .line 43
    .line 44
    invoke-virtual {v0}, Lm/p0;->getInternalPopup()Lm/o0;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    invoke-interface {v1}, Lm/o0;->a()Z

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    if-nez v1, :cond_1

    .line 53
    .line 54
    iget-object v1, v0, Lm/p0;->i:Lm/o0;

    .line 55
    .line 56
    invoke-virtual {v0}, Landroid/view/View;->getTextDirection()I

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    invoke-virtual {v0}, Landroid/view/View;->getTextAlignment()I

    .line 61
    .line 62
    .line 63
    move-result v3

    .line 64
    invoke-interface {v1, v2, v3}, Lm/o0;->j(II)V

    .line 65
    .line 66
    .line 67
    :cond_1
    invoke-virtual {v0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    if-eqz v0, :cond_2

    .line 72
    .line 73
    invoke-virtual {v0, p0}, Landroid/view/ViewTreeObserver;->removeOnGlobalLayoutListener(Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;)V

    .line 74
    .line 75
    .line 76
    :cond_2
    return-void

    .line 77
    :pswitch_1
    iget-object p0, p0, Ll/d;->e:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p0, Ll/c0;

    .line 80
    .line 81
    iget-object v0, p0, Ll/c0;->k:Lm/e2;

    .line 82
    .line 83
    invoke-virtual {p0}, Ll/c0;->a()Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-eqz v1, :cond_5

    .line 88
    .line 89
    iget-boolean v1, v0, Lm/z1;->B:Z

    .line 90
    .line 91
    if-nez v1, :cond_5

    .line 92
    .line 93
    iget-object v1, p0, Ll/c0;->p:Landroid/view/View;

    .line 94
    .line 95
    if-eqz v1, :cond_4

    .line 96
    .line 97
    invoke-virtual {v1}, Landroid/view/View;->isShown()Z

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    if-nez v1, :cond_3

    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_3
    invoke-virtual {v0}, Lm/z1;->b()V

    .line 105
    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_4
    :goto_1
    invoke-virtual {p0}, Ll/c0;->dismiss()V

    .line 109
    .line 110
    .line 111
    :cond_5
    :goto_2
    return-void

    .line 112
    :pswitch_2
    iget-object p0, p0, Ll/d;->e:Ljava/lang/Object;

    .line 113
    .line 114
    check-cast p0, Ll/f;

    .line 115
    .line 116
    iget-object v0, p0, Ll/f;->k:Ljava/util/ArrayList;

    .line 117
    .line 118
    invoke-virtual {p0}, Ll/f;->a()Z

    .line 119
    .line 120
    .line 121
    move-result v1

    .line 122
    if-eqz v1, :cond_8

    .line 123
    .line 124
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    if-lez v1, :cond_8

    .line 129
    .line 130
    const/4 v1, 0x0

    .line 131
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v1

    .line 135
    check-cast v1, Ll/e;

    .line 136
    .line 137
    iget-object v1, v1, Ll/e;->a:Lm/e2;

    .line 138
    .line 139
    iget-boolean v1, v1, Lm/z1;->B:Z

    .line 140
    .line 141
    if-nez v1, :cond_8

    .line 142
    .line 143
    iget-object v1, p0, Ll/f;->r:Landroid/view/View;

    .line 144
    .line 145
    if-eqz v1, :cond_7

    .line 146
    .line 147
    invoke-virtual {v1}, Landroid/view/View;->isShown()Z

    .line 148
    .line 149
    .line 150
    move-result v1

    .line 151
    if-nez v1, :cond_6

    .line 152
    .line 153
    goto :goto_4

    .line 154
    :cond_6
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    :goto_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 159
    .line 160
    .line 161
    move-result v0

    .line 162
    if-eqz v0, :cond_8

    .line 163
    .line 164
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    check-cast v0, Ll/e;

    .line 169
    .line 170
    iget-object v0, v0, Ll/e;->a:Lm/e2;

    .line 171
    .line 172
    invoke-virtual {v0}, Lm/z1;->b()V

    .line 173
    .line 174
    .line 175
    goto :goto_3

    .line 176
    :cond_7
    :goto_4
    invoke-virtual {p0}, Ll/f;->dismiss()V

    .line 177
    .line 178
    .line 179
    :cond_8
    return-void

    .line 180
    nop

    .line 181
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
