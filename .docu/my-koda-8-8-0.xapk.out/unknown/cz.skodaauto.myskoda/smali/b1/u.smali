.class public final Lb1/u;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/util/ArrayList;


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;I)V
    .locals 0

    .line 1
    iput p2, p0, Lb1/u;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lb1/u;->g:Ljava/util/ArrayList;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lb1/u;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lt3/d1;

    .line 7
    .line 8
    iget-object p0, p0, Lb1/u;->g:Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-ltz v0, :cond_0

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    move v2, v1

    .line 18
    :goto_0
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    check-cast v3, Lt3/e1;

    .line 23
    .line 24
    invoke-static {p1, v3, v1, v1}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 25
    .line 26
    .line 27
    if-eq v2, v0, :cond_0

    .line 28
    .line 29
    add-int/lit8 v2, v2, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_0
    check-cast p1, Lt3/d1;

    .line 36
    .line 37
    iget-object p0, p0, Lb1/u;->g:Ljava/util/ArrayList;

    .line 38
    .line 39
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    const/4 v1, 0x0

    .line 44
    move v2, v1

    .line 45
    :goto_1
    if-ge v2, v0, :cond_1

    .line 46
    .line 47
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    check-cast v3, Lt3/e1;

    .line 52
    .line 53
    invoke-static {p1, v3, v1, v1}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 54
    .line 55
    .line 56
    add-int/lit8 v2, v2, 0x1

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 60
    .line 61
    return-object p0

    .line 62
    :pswitch_1
    check-cast p1, Lt3/d1;

    .line 63
    .line 64
    iget-object p0, p0, Lb1/u;->g:Ljava/util/ArrayList;

    .line 65
    .line 66
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    const/4 v1, 0x0

    .line 71
    move v2, v1

    .line 72
    :goto_2
    if-ge v2, v0, :cond_2

    .line 73
    .line 74
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v3

    .line 78
    check-cast v3, Lt3/e1;

    .line 79
    .line 80
    invoke-static {p1, v3, v1, v1}, Lt3/d1;->p(Lt3/d1;Lt3/e1;II)V

    .line 81
    .line 82
    .line 83
    add-int/lit8 v2, v2, 0x1

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 87
    .line 88
    return-object p0

    .line 89
    :pswitch_2
    check-cast p1, Lt3/d1;

    .line 90
    .line 91
    const-string v0, "$this$layout"

    .line 92
    .line 93
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    iget-object p0, p0, Lb1/u;->g:Ljava/util/ArrayList;

    .line 97
    .line 98
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    const/4 v1, 0x0

    .line 103
    move v2, v1

    .line 104
    :goto_3
    if-ge v2, v0, :cond_3

    .line 105
    .line 106
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v3

    .line 110
    check-cast v3, Lt3/e1;

    .line 111
    .line 112
    invoke-static {p1, v3, v1, v1}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 113
    .line 114
    .line 115
    add-int/lit8 v2, v2, 0x1

    .line 116
    .line 117
    goto :goto_3

    .line 118
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 119
    .line 120
    return-object p0

    .line 121
    :pswitch_3
    check-cast p1, Lt3/d1;

    .line 122
    .line 123
    const-string v0, "$this$layout"

    .line 124
    .line 125
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    iget-object p0, p0, Lb1/u;->g:Ljava/util/ArrayList;

    .line 129
    .line 130
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    const/4 v0, 0x0

    .line 135
    move v1, v0

    .line 136
    :goto_4
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 137
    .line 138
    .line 139
    move-result v2

    .line 140
    if-eqz v2, :cond_4

    .line 141
    .line 142
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v2

    .line 146
    check-cast v2, Lt3/e1;

    .line 147
    .line 148
    invoke-static {p1, v2, v0, v1}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 149
    .line 150
    .line 151
    iget v2, v2, Lt3/e1;->e:I

    .line 152
    .line 153
    add-int/2addr v1, v2

    .line 154
    goto :goto_4

    .line 155
    :cond_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 156
    .line 157
    return-object p0

    .line 158
    :pswitch_4
    check-cast p1, Lt3/d1;

    .line 159
    .line 160
    iget-object p0, p0, Lb1/u;->g:Ljava/util/ArrayList;

    .line 161
    .line 162
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 163
    .line 164
    .line 165
    move-result v0

    .line 166
    const/4 v1, 0x0

    .line 167
    move v2, v1

    .line 168
    :goto_5
    if-ge v2, v0, :cond_5

    .line 169
    .line 170
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v3

    .line 174
    check-cast v3, Lt3/e1;

    .line 175
    .line 176
    invoke-static {p1, v3, v1, v1}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 177
    .line 178
    .line 179
    add-int/lit8 v2, v2, 0x1

    .line 180
    .line 181
    goto :goto_5

    .line 182
    :cond_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 183
    .line 184
    return-object p0

    .line 185
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
