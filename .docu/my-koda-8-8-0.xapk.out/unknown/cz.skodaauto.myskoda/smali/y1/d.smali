.class public final Ly1/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ly1/e;

.field public final b:Ly1/b;

.field public final c:Ly1/b;

.field public final d:Landroid/view/View;


# direct methods
.method public constructor <init>(Ly1/e;Ly1/b;Ly1/b;Landroid/view/View;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ly1/d;->a:Ly1/e;

    .line 5
    .line 6
    iput-object p2, p0, Ly1/d;->b:Ly1/b;

    .line 7
    .line 8
    iput-object p3, p0, Ly1/d;->c:Ly1/b;

    .line 9
    .line 10
    iput-object p4, p0, Ly1/d;->d:Landroid/view/View;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Landroid/view/Menu;)Z
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Ly1/d;->b:Ly1/b;

    .line 6
    .line 7
    invoke-virtual {v2}, Ly1/b;->invoke()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    check-cast v2, Lw1/c;

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    const/4 v4, 0x0

    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    return v4

    .line 22
    :cond_0
    invoke-interface {v1}, Landroid/view/Menu;->clear()V

    .line 23
    .line 24
    .line 25
    iget-object v2, v2, Lw1/c;->a:Ljava/lang/Object;

    .line 26
    .line 27
    move-object v3, v2

    .line 28
    check-cast v3, Ljava/util/Collection;

    .line 29
    .line 30
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    const/4 v5, 0x1

    .line 35
    move v6, v4

    .line 36
    move v7, v5

    .line 37
    move v8, v7

    .line 38
    :goto_0
    if-ge v6, v3, :cond_a

    .line 39
    .line 40
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v9

    .line 44
    check-cast v9, Lw1/b;

    .line 45
    .line 46
    instance-of v10, v9, Lw1/d;

    .line 47
    .line 48
    const/4 v11, 0x2

    .line 49
    if-eqz v10, :cond_1

    .line 50
    .line 51
    add-int/lit8 v10, v7, 0x1

    .line 52
    .line 53
    check-cast v9, Lw1/d;

    .line 54
    .line 55
    iget-object v12, v9, Lw1/d;->b:Ljava/lang/String;

    .line 56
    .line 57
    invoke-interface {v1, v8, v7, v7, v12}, Landroid/view/Menu;->add(IIILjava/lang/CharSequence;)Landroid/view/MenuItem;

    .line 58
    .line 59
    .line 60
    move-result-object v7

    .line 61
    invoke-interface {v7, v11}, Landroid/view/MenuItem;->setShowAsAction(I)V

    .line 62
    .line 63
    .line 64
    new-instance v11, Ly1/c;

    .line 65
    .line 66
    const/4 v12, 0x0

    .line 67
    invoke-direct {v11, v12, v9, v0}, Ly1/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    invoke-interface {v7, v11}, Landroid/view/MenuItem;->setOnMenuItemClickListener(Landroid/view/MenuItem$OnMenuItemClickListener;)Landroid/view/MenuItem;

    .line 71
    .line 72
    .line 73
    :goto_1
    move v7, v10

    .line 74
    goto/16 :goto_5

    .line 75
    .line 76
    :cond_1
    instance-of v10, v9, Lw1/h;

    .line 77
    .line 78
    if-eqz v10, :cond_8

    .line 79
    .line 80
    add-int/lit8 v10, v7, 0x1

    .line 81
    .line 82
    iget-object v12, v0, Ly1/d;->d:Landroid/view/View;

    .line 83
    .line 84
    invoke-virtual {v12}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 85
    .line 86
    .line 87
    move-result-object v12

    .line 88
    check-cast v9, Lw1/h;

    .line 89
    .line 90
    iget-object v13, v9, Lw1/h;->b:Landroid/view/textclassifier/TextClassification;

    .line 91
    .line 92
    iget v9, v9, Lw1/h;->c:I

    .line 93
    .line 94
    const v14, 0x1020041

    .line 95
    .line 96
    .line 97
    if-gez v9, :cond_2

    .line 98
    .line 99
    invoke-virtual {v13}, Landroid/view/textclassifier/TextClassification;->getLabel()Ljava/lang/CharSequence;

    .line 100
    .line 101
    .line 102
    move-result-object v9

    .line 103
    invoke-interface {v1, v14, v14, v7, v9}, Landroid/view/Menu;->add(IIILjava/lang/CharSequence;)Landroid/view/MenuItem;

    .line 104
    .line 105
    .line 106
    move-result-object v7

    .line 107
    invoke-interface {v7, v11}, Landroid/view/MenuItem;->setShowAsAction(I)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v13}, Landroid/view/textclassifier/TextClassification;->getIcon()Landroid/graphics/drawable/Drawable;

    .line 111
    .line 112
    .line 113
    move-result-object v9

    .line 114
    invoke-interface {v7, v9}, Landroid/view/MenuItem;->setIcon(Landroid/graphics/drawable/Drawable;)Landroid/view/MenuItem;

    .line 115
    .line 116
    .line 117
    new-instance v9, Ly1/c;

    .line 118
    .line 119
    const/4 v11, 0x1

    .line 120
    invoke-direct {v9, v11, v12, v13}, Ly1/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    invoke-interface {v7, v9}, Landroid/view/MenuItem;->setOnMenuItemClickListener(Landroid/view/MenuItem$OnMenuItemClickListener;)Landroid/view/MenuItem;

    .line 124
    .line 125
    .line 126
    goto :goto_1

    .line 127
    :cond_2
    if-nez v9, :cond_3

    .line 128
    .line 129
    move v15, v5

    .line 130
    goto :goto_2

    .line 131
    :cond_3
    move v15, v4

    .line 132
    :goto_2
    invoke-virtual {v13}, Landroid/view/textclassifier/TextClassification;->getActions()Ljava/util/List;

    .line 133
    .line 134
    .line 135
    move-result-object v13

    .line 136
    invoke-interface {v13, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v9

    .line 140
    check-cast v9, Landroid/app/RemoteAction;

    .line 141
    .line 142
    if-eqz v15, :cond_4

    .line 143
    .line 144
    move v13, v14

    .line 145
    goto :goto_3

    .line 146
    :cond_4
    move v13, v4

    .line 147
    :goto_3
    invoke-virtual {v9}, Landroid/app/RemoteAction;->getTitle()Ljava/lang/CharSequence;

    .line 148
    .line 149
    .line 150
    move-result-object v4

    .line 151
    invoke-interface {v1, v14, v13, v7, v4}, Landroid/view/Menu;->add(IIILjava/lang/CharSequence;)Landroid/view/MenuItem;

    .line 152
    .line 153
    .line 154
    move-result-object v4

    .line 155
    if-eqz v15, :cond_5

    .line 156
    .line 157
    goto :goto_4

    .line 158
    :cond_5
    const/4 v11, 0x0

    .line 159
    :goto_4
    invoke-interface {v4, v11}, Landroid/view/MenuItem;->setShowAsAction(I)V

    .line 160
    .line 161
    .line 162
    if-nez v15, :cond_6

    .line 163
    .line 164
    invoke-virtual {v9}, Landroid/app/RemoteAction;->shouldShowIcon()Z

    .line 165
    .line 166
    .line 167
    move-result v7

    .line 168
    if-eqz v7, :cond_7

    .line 169
    .line 170
    :cond_6
    invoke-virtual {v9}, Landroid/app/RemoteAction;->getIcon()Landroid/graphics/drawable/Icon;

    .line 171
    .line 172
    .line 173
    move-result-object v7

    .line 174
    invoke-virtual {v7, v12}, Landroid/graphics/drawable/Icon;->loadDrawable(Landroid/content/Context;)Landroid/graphics/drawable/Drawable;

    .line 175
    .line 176
    .line 177
    move-result-object v7

    .line 178
    invoke-interface {v4, v7}, Landroid/view/MenuItem;->setIcon(Landroid/graphics/drawable/Drawable;)Landroid/view/MenuItem;

    .line 179
    .line 180
    .line 181
    :cond_7
    new-instance v7, Ly1/p;

    .line 182
    .line 183
    invoke-direct {v7, v9}, Ly1/p;-><init>(Landroid/app/RemoteAction;)V

    .line 184
    .line 185
    .line 186
    invoke-interface {v4, v7}, Landroid/view/MenuItem;->setOnMenuItemClickListener(Landroid/view/MenuItem$OnMenuItemClickListener;)Landroid/view/MenuItem;

    .line 187
    .line 188
    .line 189
    goto :goto_1

    .line 190
    :cond_8
    instance-of v4, v9, Lw1/f;

    .line 191
    .line 192
    if-eqz v4, :cond_9

    .line 193
    .line 194
    add-int/lit8 v8, v8, 0x1

    .line 195
    .line 196
    :cond_9
    :goto_5
    add-int/lit8 v6, v6, 0x1

    .line 197
    .line 198
    const/4 v4, 0x0

    .line 199
    goto/16 :goto_0

    .line 200
    .line 201
    :cond_a
    return v5
.end method
