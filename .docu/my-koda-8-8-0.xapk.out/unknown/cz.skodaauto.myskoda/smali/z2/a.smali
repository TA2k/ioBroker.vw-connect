.class public final synthetic Lz2/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lz2/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lz2/a;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lz2/a;->d:I

    .line 4
    .line 5
    iget-object v0, v0, Lz2/a;->e:Ljava/lang/Object;

    .line 6
    .line 7
    packed-switch v1, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    check-cast v0, Lcom/google/android/material/textfield/TextInputLayout;

    .line 11
    .line 12
    iget-object v0, v0, Lcom/google/android/material/textfield/TextInputLayout;->h:Landroid/widget/EditText;

    .line 13
    .line 14
    invoke-virtual {v0}, Landroid/view/View;->requestLayout()V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_0
    check-cast v0, Lzq/i;

    .line 19
    .line 20
    iget-object v1, v0, Lzq/i;->h:Landroid/widget/AutoCompleteTextView;

    .line 21
    .line 22
    invoke-virtual {v1}, Landroid/widget/AutoCompleteTextView;->isPopupShowing()Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    invoke-virtual {v0, v1}, Lzq/i;->s(Z)V

    .line 27
    .line 28
    .line 29
    iput-boolean v1, v0, Lzq/i;->m:Z

    .line 30
    .line 31
    return-void

    .line 32
    :pswitch_1
    check-cast v0, Lzq/c;

    .line 33
    .line 34
    const/4 v1, 0x1

    .line 35
    invoke-virtual {v0, v1}, Lzq/c;->s(Z)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :pswitch_2
    check-cast v0, Lz2/e;

    .line 40
    .line 41
    invoke-virtual {v0}, Lz2/e;->e()Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    iget-object v2, v0, Lz2/e;->d:Lw3/t;

    .line 46
    .line 47
    if-nez v1, :cond_0

    .line 48
    .line 49
    goto/16 :goto_4

    .line 50
    .line 51
    :cond_0
    const-string v1, "ContentCapture:changeChecker"

    .line 52
    .line 53
    invoke-static {v1}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    const/4 v1, 0x1

    .line 57
    :try_start_0
    invoke-virtual {v2, v1}, Lw3/t;->r(Z)V

    .line 58
    .line 59
    .line 60
    iget-object v1, v0, Lz2/e;->o:Landroidx/collection/b0;

    .line 61
    .line 62
    iget-object v3, v1, Landroidx/collection/p;->b:[I

    .line 63
    .line 64
    iget-object v1, v1, Landroidx/collection/p;->a:[J

    .line 65
    .line 66
    array-length v4, v1

    .line 67
    add-int/lit8 v4, v4, -0x2

    .line 68
    .line 69
    if-ltz v4, :cond_4

    .line 70
    .line 71
    const/4 v6, 0x0

    .line 72
    :goto_0
    aget-wide v7, v1, v6

    .line 73
    .line 74
    not-long v9, v7

    .line 75
    const/4 v11, 0x7

    .line 76
    shl-long/2addr v9, v11

    .line 77
    and-long/2addr v9, v7

    .line 78
    const-wide v11, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 79
    .line 80
    .line 81
    .line 82
    .line 83
    and-long/2addr v9, v11

    .line 84
    cmp-long v9, v9, v11

    .line 85
    .line 86
    if-eqz v9, :cond_3

    .line 87
    .line 88
    sub-int v9, v6, v4

    .line 89
    .line 90
    not-int v9, v9

    .line 91
    ushr-int/lit8 v9, v9, 0x1f

    .line 92
    .line 93
    const/16 v10, 0x8

    .line 94
    .line 95
    rsub-int/lit8 v9, v9, 0x8

    .line 96
    .line 97
    const/4 v11, 0x0

    .line 98
    :goto_1
    if-ge v11, v9, :cond_2

    .line 99
    .line 100
    const-wide/16 v12, 0xff

    .line 101
    .line 102
    and-long/2addr v12, v7

    .line 103
    const-wide/16 v14, 0x80

    .line 104
    .line 105
    cmp-long v12, v12, v14

    .line 106
    .line 107
    if-gez v12, :cond_1

    .line 108
    .line 109
    shl-int/lit8 v12, v6, 0x3

    .line 110
    .line 111
    add-int/2addr v12, v11

    .line 112
    aget v14, v3, v12

    .line 113
    .line 114
    invoke-virtual {v0}, Lz2/e;->d()Landroidx/collection/p;

    .line 115
    .line 116
    .line 117
    move-result-object v12

    .line 118
    invoke-virtual {v12, v14}, Landroidx/collection/p;->a(I)Z

    .line 119
    .line 120
    .line 121
    move-result v12

    .line 122
    if-nez v12, :cond_1

    .line 123
    .line 124
    iget-object v12, v0, Lz2/e;->g:Ljava/util/ArrayList;

    .line 125
    .line 126
    new-instance v13, Lz2/f;

    .line 127
    .line 128
    move/from16 v19, v6

    .line 129
    .line 130
    iget-wide v5, v0, Lz2/e;->n:J

    .line 131
    .line 132
    sget-object v17, Lz2/g;->e:Lz2/g;

    .line 133
    .line 134
    const/16 v18, 0x0

    .line 135
    .line 136
    move-wide v15, v5

    .line 137
    invoke-direct/range {v13 .. v18}, Lz2/f;-><init>(IJLz2/g;Lyn/e;)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {v12, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    iget-object v5, v0, Lz2/e;->k:Lxy0/j;

    .line 144
    .line 145
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 146
    .line 147
    invoke-interface {v5, v6}, Lxy0/a0;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    goto :goto_2

    .line 151
    :cond_1
    move/from16 v19, v6

    .line 152
    .line 153
    :goto_2
    shr-long/2addr v7, v10

    .line 154
    add-int/lit8 v11, v11, 0x1

    .line 155
    .line 156
    move/from16 v6, v19

    .line 157
    .line 158
    goto :goto_1

    .line 159
    :cond_2
    move/from16 v19, v6

    .line 160
    .line 161
    if-ne v9, v10, :cond_4

    .line 162
    .line 163
    move/from16 v5, v19

    .line 164
    .line 165
    goto :goto_3

    .line 166
    :cond_3
    move v5, v6

    .line 167
    :goto_3
    if-eq v5, v4, :cond_4

    .line 168
    .line 169
    add-int/lit8 v6, v5, 0x1

    .line 170
    .line 171
    goto :goto_0

    .line 172
    :cond_4
    const-string v1, "ContentCapture:sendAppearEvents"

    .line 173
    .line 174
    invoke-static {v1}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 175
    .line 176
    .line 177
    :try_start_1
    invoke-virtual {v2}, Lw3/t;->getSemanticsOwner()Ld4/s;

    .line 178
    .line 179
    .line 180
    move-result-object v1

    .line 181
    invoke-virtual {v1}, Ld4/s;->a()Ld4/q;

    .line 182
    .line 183
    .line 184
    move-result-object v1

    .line 185
    iget-object v2, v0, Lz2/e;->p:Lw3/a2;

    .line 186
    .line 187
    invoke-virtual {v0, v1, v2}, Lz2/e;->h(Ld4/q;Lw3/a2;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 188
    .line 189
    .line 190
    :try_start_2
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 191
    .line 192
    .line 193
    invoke-virtual {v0}, Lz2/e;->d()Landroidx/collection/p;

    .line 194
    .line 195
    .line 196
    move-result-object v1

    .line 197
    invoke-virtual {v0, v1}, Lz2/e;->b(Landroidx/collection/p;)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {v0}, Lz2/e;->k()V

    .line 201
    .line 202
    .line 203
    const/4 v1, 0x0

    .line 204
    iput-boolean v1, v0, Lz2/e;->q:Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 205
    .line 206
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 207
    .line 208
    .line 209
    :goto_4
    return-void

    .line 210
    :catchall_0
    move-exception v0

    .line 211
    :try_start_3
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 212
    .line 213
    .line 214
    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 215
    :catchall_1
    move-exception v0

    .line 216
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 217
    .line 218
    .line 219
    throw v0

    .line 220
    nop

    .line 221
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
