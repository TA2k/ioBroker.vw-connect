.class public final synthetic Lcz/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/List;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(ILay0/k;Ljava/util/List;Ljava/util/List;)V
    .locals 0

    .line 1
    const/4 p1, 0x0

    iput p1, p0, Lcz/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p3, p0, Lcz/a;->e:Ljava/util/List;

    iput-object p4, p0, Lcz/a;->g:Ljava/util/List;

    iput-object p2, p0, Lcz/a;->f:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;Lay0/k;Ljava/util/List;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lcz/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcz/a;->e:Ljava/util/List;

    iput-object p2, p0, Lcz/a;->f:Lay0/k;

    iput-object p3, p0, Lcz/a;->g:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lcz/a;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

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
    and-int/lit8 v3, v2, 0x3

    .line 21
    .line 22
    const/4 v4, 0x2

    .line 23
    const/4 v5, 0x1

    .line 24
    if-eq v3, v4, :cond_0

    .line 25
    .line 26
    move v3, v5

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v3, 0x0

    .line 29
    :goto_0
    and-int/2addr v2, v5

    .line 30
    move-object v14, v1

    .line 31
    check-cast v14, Ll2/t;

    .line 32
    .line 33
    invoke-virtual {v14, v2, v3}, Ll2/t;->O(IZ)Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    if-eqz v1, :cond_3

    .line 40
    .line 41
    iget-object v1, v0, Lcz/a;->e:Ljava/util/List;

    .line 42
    .line 43
    check-cast v1, Ljava/lang/Iterable;

    .line 44
    .line 45
    new-instance v3, Ljava/util/ArrayList;

    .line 46
    .line 47
    const/16 v4, 0xa

    .line 48
    .line 49
    invoke-static {v1, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 54
    .line 55
    .line 56
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    if-eqz v4, :cond_4

    .line 65
    .line 66
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v4

    .line 70
    check-cast v4, Laz/a;

    .line 71
    .line 72
    iget v5, v4, Laz/a;->d:I

    .line 73
    .line 74
    invoke-static {v14, v5}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v5

    .line 78
    iget-object v6, v0, Lcz/a;->f:Lay0/k;

    .line 79
    .line 80
    invoke-virtual {v14, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v7

    .line 84
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 85
    .line 86
    .line 87
    move-result v8

    .line 88
    invoke-virtual {v14, v8}, Ll2/t;->e(I)Z

    .line 89
    .line 90
    .line 91
    move-result v8

    .line 92
    or-int/2addr v7, v8

    .line 93
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v8

    .line 97
    if-nez v7, :cond_1

    .line 98
    .line 99
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 100
    .line 101
    if-ne v8, v7, :cond_2

    .line 102
    .line 103
    :cond_1
    new-instance v8, Laa/k;

    .line 104
    .line 105
    const/16 v7, 0x16

    .line 106
    .line 107
    invoke-direct {v8, v7, v6, v4}, Laa/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v14, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    :cond_2
    move-object v6, v8

    .line 114
    check-cast v6, Lay0/a;

    .line 115
    .line 116
    iget-object v7, v0, Lcz/a;->g:Ljava/util/List;

    .line 117
    .line 118
    invoke-interface {v7, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v7

    .line 122
    iget-object v4, v4, Laz/a;->e:Ljava/lang/String;

    .line 123
    .line 124
    const-string v8, "ai_trip_interests_selection_food_item_"

    .line 125
    .line 126
    invoke-virtual {v8, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v13

    .line 130
    const/16 v16, 0x0

    .line 131
    .line 132
    const/16 v17, 0x1ff2

    .line 133
    .line 134
    move-object v4, v5

    .line 135
    const/4 v5, 0x0

    .line 136
    const/4 v8, 0x0

    .line 137
    const/4 v9, 0x0

    .line 138
    const/4 v10, 0x0

    .line 139
    const/4 v11, 0x0

    .line 140
    const/4 v12, 0x0

    .line 141
    const/4 v15, 0x0

    .line 142
    invoke-static/range {v4 .. v17}, Li91/h0;->a(Ljava/lang/String;Lx2/s;Lay0/a;ZZZLjava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;III)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    goto :goto_1

    .line 149
    :cond_3
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 150
    .line 151
    .line 152
    :cond_4
    return-object v2

    .line 153
    :pswitch_0
    move-object/from16 v1, p1

    .line 154
    .line 155
    check-cast v1, Ll2/o;

    .line 156
    .line 157
    move-object/from16 v2, p2

    .line 158
    .line 159
    check-cast v2, Ljava/lang/Integer;

    .line 160
    .line 161
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 162
    .line 163
    .line 164
    const/4 v2, 0x1

    .line 165
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 166
    .line 167
    .line 168
    move-result v2

    .line 169
    iget-object v3, v0, Lcz/a;->e:Ljava/util/List;

    .line 170
    .line 171
    iget-object v4, v0, Lcz/a;->g:Ljava/util/List;

    .line 172
    .line 173
    iget-object v0, v0, Lcz/a;->f:Lay0/k;

    .line 174
    .line 175
    invoke-static {v3, v4, v0, v1, v2}, Lcz/t;->v(Ljava/util/List;Ljava/util/List;Lay0/k;Ll2/o;I)V

    .line 176
    .line 177
    .line 178
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 179
    .line 180
    return-object v0

    .line 181
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
