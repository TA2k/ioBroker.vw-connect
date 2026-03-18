.class public final synthetic Lh2/s1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:I

.field public final synthetic i:Ljava/lang/Comparable;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Llx0/e;

.field public final synthetic m:Llx0/e;

.field public final synthetic n:Ljava/lang/Object;

.field public final synthetic o:Ljava/lang/Object;

.field public final synthetic p:Ljava/lang/Object;

.field public final synthetic q:Ljava/lang/Object;

.field public final synthetic r:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Landroid/net/Uri;Lx2/s;Landroid/graphics/Bitmap;Lay0/a;Lay0/a;Lay0/a;Lx2/e;Lt3/k;Ljava/util/List;Lay0/n;Lay0/n;III)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lh2/s1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/s1;->i:Ljava/lang/Comparable;

    iput-object p2, p0, Lh2/s1;->e:Lx2/s;

    iput-object p3, p0, Lh2/s1;->j:Ljava/lang/Object;

    iput-object p4, p0, Lh2/s1;->k:Ljava/lang/Object;

    iput-object p5, p0, Lh2/s1;->l:Llx0/e;

    iput-object p6, p0, Lh2/s1;->m:Llx0/e;

    iput-object p7, p0, Lh2/s1;->n:Ljava/lang/Object;

    iput-object p8, p0, Lh2/s1;->o:Ljava/lang/Object;

    iput-object p9, p0, Lh2/s1;->p:Ljava/lang/Object;

    iput-object p10, p0, Lh2/s1;->q:Ljava/lang/Object;

    iput-object p11, p0, Lh2/s1;->r:Ljava/lang/Object;

    iput p12, p0, Lh2/s1;->f:I

    iput p13, p0, Lh2/s1;->g:I

    iput p14, p0, Lh2/s1;->h:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Ljava/lang/Long;Lay0/k;Li2/z;Lt2/b;Lt2/b;ILh2/y1;Li2/e0;Ljava/util/Locale;Lh2/z1;Lc3/q;II)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lh2/s1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/s1;->e:Lx2/s;

    iput-object p2, p0, Lh2/s1;->i:Ljava/lang/Comparable;

    iput-object p3, p0, Lh2/s1;->j:Ljava/lang/Object;

    iput-object p4, p0, Lh2/s1;->k:Ljava/lang/Object;

    iput-object p5, p0, Lh2/s1;->l:Llx0/e;

    iput-object p6, p0, Lh2/s1;->m:Llx0/e;

    iput p7, p0, Lh2/s1;->f:I

    iput-object p8, p0, Lh2/s1;->n:Ljava/lang/Object;

    iput-object p9, p0, Lh2/s1;->o:Ljava/lang/Object;

    iput-object p10, p0, Lh2/s1;->p:Ljava/lang/Object;

    iput-object p11, p0, Lh2/s1;->q:Ljava/lang/Object;

    iput-object p12, p0, Lh2/s1;->r:Ljava/lang/Object;

    iput p13, p0, Lh2/s1;->g:I

    iput p14, p0, Lh2/s1;->h:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh2/s1;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lh2/s1;->i:Ljava/lang/Comparable;

    .line 9
    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Landroid/net/Uri;

    .line 12
    .line 13
    iget-object v1, v0, Lh2/s1;->j:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v4, v1

    .line 16
    check-cast v4, Landroid/graphics/Bitmap;

    .line 17
    .line 18
    iget-object v1, v0, Lh2/s1;->k:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v5, v1

    .line 21
    check-cast v5, Lay0/a;

    .line 22
    .line 23
    iget-object v1, v0, Lh2/s1;->l:Llx0/e;

    .line 24
    .line 25
    move-object v6, v1

    .line 26
    check-cast v6, Lay0/a;

    .line 27
    .line 28
    iget-object v1, v0, Lh2/s1;->m:Llx0/e;

    .line 29
    .line 30
    move-object v7, v1

    .line 31
    check-cast v7, Lay0/a;

    .line 32
    .line 33
    iget-object v1, v0, Lh2/s1;->n:Ljava/lang/Object;

    .line 34
    .line 35
    move-object v8, v1

    .line 36
    check-cast v8, Lx2/e;

    .line 37
    .line 38
    iget-object v1, v0, Lh2/s1;->o:Ljava/lang/Object;

    .line 39
    .line 40
    move-object v9, v1

    .line 41
    check-cast v9, Lt3/k;

    .line 42
    .line 43
    iget-object v1, v0, Lh2/s1;->p:Ljava/lang/Object;

    .line 44
    .line 45
    move-object v10, v1

    .line 46
    check-cast v10, Ljava/util/List;

    .line 47
    .line 48
    iget-object v1, v0, Lh2/s1;->q:Ljava/lang/Object;

    .line 49
    .line 50
    move-object v11, v1

    .line 51
    check-cast v11, Lay0/n;

    .line 52
    .line 53
    iget-object v1, v0, Lh2/s1;->r:Ljava/lang/Object;

    .line 54
    .line 55
    move-object v12, v1

    .line 56
    check-cast v12, Lay0/n;

    .line 57
    .line 58
    move-object/from16 v13, p1

    .line 59
    .line 60
    check-cast v13, Ll2/o;

    .line 61
    .line 62
    move-object/from16 v1, p2

    .line 63
    .line 64
    check-cast v1, Ljava/lang/Integer;

    .line 65
    .line 66
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    iget v1, v0, Lh2/s1;->f:I

    .line 70
    .line 71
    or-int/lit8 v1, v1, 0x1

    .line 72
    .line 73
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 74
    .line 75
    .line 76
    move-result v14

    .line 77
    iget v1, v0, Lh2/s1;->g:I

    .line 78
    .line 79
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 80
    .line 81
    .line 82
    move-result v15

    .line 83
    iget-object v3, v0, Lh2/s1;->e:Lx2/s;

    .line 84
    .line 85
    iget v0, v0, Lh2/s1;->h:I

    .line 86
    .line 87
    move/from16 v16, v0

    .line 88
    .line 89
    invoke-static/range {v2 .. v16}, Lxf0/i0;->F(Landroid/net/Uri;Lx2/s;Landroid/graphics/Bitmap;Lay0/a;Lay0/a;Lay0/a;Lx2/e;Lt3/k;Ljava/util/List;Lay0/n;Lay0/n;Ll2/o;III)V

    .line 90
    .line 91
    .line 92
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    return-object v0

    .line 95
    :pswitch_0
    iget-object v1, v0, Lh2/s1;->i:Ljava/lang/Comparable;

    .line 96
    .line 97
    move-object v3, v1

    .line 98
    check-cast v3, Ljava/lang/Long;

    .line 99
    .line 100
    iget-object v1, v0, Lh2/s1;->j:Ljava/lang/Object;

    .line 101
    .line 102
    move-object v4, v1

    .line 103
    check-cast v4, Lay0/k;

    .line 104
    .line 105
    iget-object v1, v0, Lh2/s1;->k:Ljava/lang/Object;

    .line 106
    .line 107
    move-object v5, v1

    .line 108
    check-cast v5, Li2/z;

    .line 109
    .line 110
    iget-object v1, v0, Lh2/s1;->l:Llx0/e;

    .line 111
    .line 112
    move-object v6, v1

    .line 113
    check-cast v6, Lt2/b;

    .line 114
    .line 115
    iget-object v1, v0, Lh2/s1;->m:Llx0/e;

    .line 116
    .line 117
    move-object v7, v1

    .line 118
    check-cast v7, Lt2/b;

    .line 119
    .line 120
    iget-object v1, v0, Lh2/s1;->n:Ljava/lang/Object;

    .line 121
    .line 122
    move-object v9, v1

    .line 123
    check-cast v9, Lh2/y1;

    .line 124
    .line 125
    iget-object v1, v0, Lh2/s1;->o:Ljava/lang/Object;

    .line 126
    .line 127
    move-object v10, v1

    .line 128
    check-cast v10, Li2/e0;

    .line 129
    .line 130
    iget-object v1, v0, Lh2/s1;->p:Ljava/lang/Object;

    .line 131
    .line 132
    move-object v11, v1

    .line 133
    check-cast v11, Ljava/util/Locale;

    .line 134
    .line 135
    iget-object v1, v0, Lh2/s1;->q:Ljava/lang/Object;

    .line 136
    .line 137
    move-object v12, v1

    .line 138
    check-cast v12, Lh2/z1;

    .line 139
    .line 140
    iget-object v1, v0, Lh2/s1;->r:Ljava/lang/Object;

    .line 141
    .line 142
    move-object v13, v1

    .line 143
    check-cast v13, Lc3/q;

    .line 144
    .line 145
    move-object/from16 v14, p1

    .line 146
    .line 147
    check-cast v14, Ll2/o;

    .line 148
    .line 149
    move-object/from16 v1, p2

    .line 150
    .line 151
    check-cast v1, Ljava/lang/Integer;

    .line 152
    .line 153
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 154
    .line 155
    .line 156
    iget v1, v0, Lh2/s1;->g:I

    .line 157
    .line 158
    or-int/lit8 v1, v1, 0x1

    .line 159
    .line 160
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 161
    .line 162
    .line 163
    move-result v15

    .line 164
    iget v1, v0, Lh2/s1;->h:I

    .line 165
    .line 166
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 167
    .line 168
    .line 169
    move-result v16

    .line 170
    iget-object v2, v0, Lh2/s1;->e:Lx2/s;

    .line 171
    .line 172
    iget v8, v0, Lh2/s1;->f:I

    .line 173
    .line 174
    invoke-static/range {v2 .. v16}, Lh2/x1;->b(Lx2/s;Ljava/lang/Long;Lay0/k;Li2/z;Lt2/b;Lt2/b;ILh2/y1;Li2/e0;Ljava/util/Locale;Lh2/z1;Lc3/q;Ll2/o;II)V

    .line 175
    .line 176
    .line 177
    goto :goto_0

    .line 178
    nop

    .line 179
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
