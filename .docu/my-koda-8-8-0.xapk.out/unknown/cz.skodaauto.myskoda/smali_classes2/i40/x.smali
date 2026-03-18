.class public final synthetic Li40/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;I)V
    .locals 0

    .line 1
    iput p2, p0, Li40/x;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li40/x;->e:Ljava/util/List;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li40/x;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lp1/p;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    move-object/from16 v18, p3

    .line 21
    .line 22
    check-cast v18, Ll2/o;

    .line 23
    .line 24
    move-object/from16 v3, p4

    .line 25
    .line 26
    check-cast v3, Ljava/lang/Integer;

    .line 27
    .line 28
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    const-string v3, "$this$HorizontalPager"

    .line 32
    .line 33
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    iget-object v0, v0, Li40/x;->e:Ljava/util/List;

    .line 37
    .line 38
    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    move-object v3, v0

    .line 43
    check-cast v3, Landroid/net/Uri;

    .line 44
    .line 45
    sget-object v4, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 46
    .line 47
    const/16 v20, 0x0

    .line 48
    .line 49
    const v21, 0x1fffc

    .line 50
    .line 51
    .line 52
    const/4 v5, 0x0

    .line 53
    const/4 v6, 0x0

    .line 54
    const/4 v7, 0x0

    .line 55
    const/4 v8, 0x0

    .line 56
    const/4 v9, 0x0

    .line 57
    const/4 v10, 0x0

    .line 58
    const/4 v11, 0x0

    .line 59
    const/4 v12, 0x0

    .line 60
    const/4 v13, 0x0

    .line 61
    const/4 v14, 0x0

    .line 62
    const/4 v15, 0x0

    .line 63
    const/16 v16, 0x0

    .line 64
    .line 65
    const/16 v17, 0x0

    .line 66
    .line 67
    const/16 v19, 0x30

    .line 68
    .line 69
    invoke-static/range {v3 .. v21}, Lxf0/i0;->c(Landroid/net/Uri;Lx2/s;Lay0/a;Lay0/a;Lay0/a;Ld01/h0;Lx2/e;Lt3/k;Ljava/util/List;Li3/c;Li3/c;Li3/c;ZZLe3/m;Ll2/o;III)V

    .line 70
    .line 71
    .line 72
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 73
    .line 74
    return-object v0

    .line 75
    :pswitch_0
    move-object/from16 v1, p1

    .line 76
    .line 77
    check-cast v1, Lp1/p;

    .line 78
    .line 79
    move-object/from16 v2, p2

    .line 80
    .line 81
    check-cast v2, Ljava/lang/Integer;

    .line 82
    .line 83
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    move-object/from16 v3, p3

    .line 88
    .line 89
    check-cast v3, Ll2/o;

    .line 90
    .line 91
    move-object/from16 v4, p4

    .line 92
    .line 93
    check-cast v4, Ljava/lang/Integer;

    .line 94
    .line 95
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 96
    .line 97
    .line 98
    const-string v4, "$this$HorizontalPager"

    .line 99
    .line 100
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    add-int/lit8 v2, v2, 0x1

    .line 104
    .line 105
    iget-object v0, v0, Li40/x;->e:Ljava/util/List;

    .line 106
    .line 107
    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    check-cast v0, Lay0/n;

    .line 112
    .line 113
    const/4 v1, 0x0

    .line 114
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 115
    .line 116
    .line 117
    move-result-object v1

    .line 118
    invoke-interface {v0, v3, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    goto :goto_0

    .line 122
    :pswitch_1
    move-object/from16 v1, p1

    .line 123
    .line 124
    check-cast v1, Lp1/p;

    .line 125
    .line 126
    move-object/from16 v2, p2

    .line 127
    .line 128
    check-cast v2, Ljava/lang/Integer;

    .line 129
    .line 130
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 131
    .line 132
    .line 133
    move-result v2

    .line 134
    move-object/from16 v14, p3

    .line 135
    .line 136
    check-cast v14, Ll2/o;

    .line 137
    .line 138
    move-object/from16 v3, p4

    .line 139
    .line 140
    check-cast v3, Ljava/lang/Integer;

    .line 141
    .line 142
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 143
    .line 144
    .line 145
    const-string v3, "$this$HorizontalPager"

    .line 146
    .line 147
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    const/high16 v1, 0x3f800000    # 1.0f

    .line 151
    .line 152
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 153
    .line 154
    invoke-static {v3, v1}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    sget v3, Li40/e0;->b:F

    .line 159
    .line 160
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 161
    .line 162
    .line 163
    move-result-object v4

    .line 164
    iget-object v0, v0, Li40/x;->e:Ljava/util/List;

    .line 165
    .line 166
    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    check-cast v0, Lh40/c;

    .line 171
    .line 172
    iget-object v0, v0, Lh40/c;->c:Ljava/lang/String;

    .line 173
    .line 174
    if-eqz v0, :cond_0

    .line 175
    .line 176
    invoke-static {v0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 177
    .line 178
    .line 179
    move-result-object v0

    .line 180
    :goto_1
    move-object v3, v0

    .line 181
    goto :goto_2

    .line 182
    :cond_0
    const/4 v0, 0x0

    .line 183
    goto :goto_1

    .line 184
    :goto_2
    sget-object v12, Li40/q;->h:Lt2/b;

    .line 185
    .line 186
    sget-object v13, Li40/q;->i:Lt2/b;

    .line 187
    .line 188
    const/16 v16, 0x6c00

    .line 189
    .line 190
    const/16 v17, 0x1ffc

    .line 191
    .line 192
    const/4 v5, 0x0

    .line 193
    const/4 v6, 0x0

    .line 194
    const/4 v7, 0x0

    .line 195
    const/4 v8, 0x0

    .line 196
    const/4 v9, 0x0

    .line 197
    const/4 v10, 0x0

    .line 198
    const/4 v11, 0x0

    .line 199
    const/16 v15, 0x30

    .line 200
    .line 201
    invoke-static/range {v3 .. v17}, Lxf0/i0;->F(Landroid/net/Uri;Lx2/s;Landroid/graphics/Bitmap;Lay0/a;Lay0/a;Lay0/a;Lx2/e;Lt3/k;Ljava/util/List;Lay0/n;Lay0/n;Ll2/o;III)V

    .line 202
    .line 203
    .line 204
    goto/16 :goto_0

    .line 205
    .line 206
    nop

    .line 207
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
