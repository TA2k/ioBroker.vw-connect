.class public final Lka/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/ArrayList;

.field public final synthetic f:Lka/h;


# direct methods
.method public synthetic constructor <init>(Lka/h;Ljava/util/ArrayList;I)V
    .locals 0

    .line 1
    iput p3, p0, Lka/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lka/b;->f:Lka/h;

    .line 4
    .line 5
    iput-object p2, p0, Lka/b;->e:Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 12

    .line 1
    iget v0, p0, Lka/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lka/b;->e:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    iget-object v3, p0, Lka/b;->f:Lka/h;

    .line 17
    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    check-cast v2, Lka/v0;

    .line 25
    .line 26
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    iget-object v4, v2, Lka/v0;->a:Landroid/view/View;

    .line 30
    .line 31
    invoke-virtual {v4}, Landroid/view/View;->animate()Landroid/view/ViewPropertyAnimator;

    .line 32
    .line 33
    .line 34
    move-result-object v5

    .line 35
    iget-object v6, v3, Lka/h;->o:Ljava/util/ArrayList;

    .line 36
    .line 37
    invoke-virtual {v6, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    const/high16 v6, 0x3f800000    # 1.0f

    .line 41
    .line 42
    invoke-virtual {v5, v6}, Landroid/view/ViewPropertyAnimator;->alpha(F)Landroid/view/ViewPropertyAnimator;

    .line 43
    .line 44
    .line 45
    move-result-object v6

    .line 46
    iget-wide v7, v3, Lka/c0;->c:J

    .line 47
    .line 48
    invoke-virtual {v6, v7, v8}, Landroid/view/ViewPropertyAnimator;->setDuration(J)Landroid/view/ViewPropertyAnimator;

    .line 49
    .line 50
    .line 51
    move-result-object v6

    .line 52
    new-instance v7, Lka/c;

    .line 53
    .line 54
    invoke-direct {v7, v3, v2, v4, v5}, Lka/c;-><init>(Lka/h;Lka/v0;Landroid/view/View;Landroid/view/ViewPropertyAnimator;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v6, v7}, Landroid/view/ViewPropertyAnimator;->setListener(Landroid/animation/Animator$AnimatorListener;)Landroid/view/ViewPropertyAnimator;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    invoke-virtual {v2}, Landroid/view/ViewPropertyAnimator;->start()V

    .line 62
    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_0
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 66
    .line 67
    .line 68
    iget-object p0, v3, Lka/h;->l:Ljava/util/ArrayList;

    .line 69
    .line 70
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    return-void

    .line 74
    :pswitch_0
    iget-object v0, p0, Lka/b;->e:Ljava/util/ArrayList;

    .line 75
    .line 76
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    iget-object v4, p0, Lka/b;->f:Lka/h;

    .line 85
    .line 86
    if-eqz v2, :cond_3

    .line 87
    .line 88
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    check-cast v2, Lka/g;

    .line 93
    .line 94
    iget-object v5, v2, Lka/g;->a:Lka/v0;

    .line 95
    .line 96
    iget v3, v2, Lka/g;->b:I

    .line 97
    .line 98
    iget v6, v2, Lka/g;->c:I

    .line 99
    .line 100
    iget v7, v2, Lka/g;->d:I

    .line 101
    .line 102
    iget v2, v2, Lka/g;->e:I

    .line 103
    .line 104
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 105
    .line 106
    .line 107
    move v8, v7

    .line 108
    iget-object v7, v5, Lka/v0;->a:Landroid/view/View;

    .line 109
    .line 110
    sub-int v3, v8, v3

    .line 111
    .line 112
    sub-int v8, v2, v6

    .line 113
    .line 114
    const/4 v2, 0x0

    .line 115
    if-eqz v3, :cond_1

    .line 116
    .line 117
    invoke-virtual {v7}, Landroid/view/View;->animate()Landroid/view/ViewPropertyAnimator;

    .line 118
    .line 119
    .line 120
    move-result-object v6

    .line 121
    invoke-virtual {v6, v2}, Landroid/view/ViewPropertyAnimator;->translationX(F)Landroid/view/ViewPropertyAnimator;

    .line 122
    .line 123
    .line 124
    :cond_1
    if-eqz v8, :cond_2

    .line 125
    .line 126
    invoke-virtual {v7}, Landroid/view/View;->animate()Landroid/view/ViewPropertyAnimator;

    .line 127
    .line 128
    .line 129
    move-result-object v6

    .line 130
    invoke-virtual {v6, v2}, Landroid/view/ViewPropertyAnimator;->translationY(F)Landroid/view/ViewPropertyAnimator;

    .line 131
    .line 132
    .line 133
    :cond_2
    invoke-virtual {v7}, Landroid/view/View;->animate()Landroid/view/ViewPropertyAnimator;

    .line 134
    .line 135
    .line 136
    move-result-object v9

    .line 137
    iget-object v2, v4, Lka/h;->p:Ljava/util/ArrayList;

    .line 138
    .line 139
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    iget-wide v10, v4, Lka/c0;->e:J

    .line 143
    .line 144
    invoke-virtual {v9, v10, v11}, Landroid/view/ViewPropertyAnimator;->setDuration(J)Landroid/view/ViewPropertyAnimator;

    .line 145
    .line 146
    .line 147
    move-result-object v2

    .line 148
    move v6, v3

    .line 149
    new-instance v3, Lka/d;

    .line 150
    .line 151
    invoke-direct/range {v3 .. v9}, Lka/d;-><init>(Lka/h;Lka/v0;ILandroid/view/View;ILandroid/view/ViewPropertyAnimator;)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v2, v3}, Landroid/view/ViewPropertyAnimator;->setListener(Landroid/animation/Animator$AnimatorListener;)Landroid/view/ViewPropertyAnimator;

    .line 155
    .line 156
    .line 157
    move-result-object v2

    .line 158
    invoke-virtual {v2}, Landroid/view/ViewPropertyAnimator;->start()V

    .line 159
    .line 160
    .line 161
    goto :goto_1

    .line 162
    :cond_3
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 163
    .line 164
    .line 165
    iget-object p0, v4, Lka/h;->m:Ljava/util/ArrayList;

    .line 166
    .line 167
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    return-void

    .line 171
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
