.class public final synthetic Lh2/cb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Ljava/util/ArrayList;

.field public final synthetic e:Lt3/p1;

.field public final synthetic f:Lt2/b;

.field public final synthetic g:Lkotlin/jvm/internal/d0;

.field public final synthetic h:Lt4/a;

.field public final synthetic i:I

.field public final synthetic j:Lt2/b;

.field public final synthetic k:Ljava/util/ArrayList;

.field public final synthetic l:I


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;Lt3/p1;Lt2/b;Lkotlin/jvm/internal/d0;Lt4/a;ILt2/b;Ljava/util/ArrayList;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/cb;->d:Ljava/util/ArrayList;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/cb;->e:Lt3/p1;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/cb;->f:Lt2/b;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/cb;->g:Lkotlin/jvm/internal/d0;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/cb;->h:Lt4/a;

    .line 13
    .line 14
    iput p6, p0, Lh2/cb;->i:I

    .line 15
    .line 16
    iput-object p7, p0, Lh2/cb;->j:Lt2/b;

    .line 17
    .line 18
    iput-object p8, p0, Lh2/cb;->k:Ljava/util/ArrayList;

    .line 19
    .line 20
    iput p9, p0, Lh2/cb;->l:I

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lt3/d1;

    .line 6
    .line 7
    iget-object v2, v0, Lh2/cb;->d:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    const/4 v4, 0x0

    .line 14
    move v5, v4

    .line 15
    :goto_0
    if-ge v5, v3, :cond_0

    .line 16
    .line 17
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v6

    .line 21
    check-cast v6, Lt3/e1;

    .line 22
    .line 23
    iget-object v7, v0, Lh2/cb;->g:Lkotlin/jvm/internal/d0;

    .line 24
    .line 25
    iget v7, v7, Lkotlin/jvm/internal/d0;->d:I

    .line 26
    .line 27
    mul-int/2addr v7, v5

    .line 28
    invoke-static {v1, v6, v7, v4}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 29
    .line 30
    .line 31
    add-int/lit8 v5, v5, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    sget-object v2, Lh2/db;->e:Lh2/db;

    .line 35
    .line 36
    iget-object v3, v0, Lh2/cb;->e:Lt3/p1;

    .line 37
    .line 38
    iget-object v5, v0, Lh2/cb;->f:Lt2/b;

    .line 39
    .line 40
    invoke-interface {v3, v2, v5}, Lt3/p1;->C(Ljava/lang/Object;Lay0/n;)Ljava/util/List;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    move-object v5, v2

    .line 45
    check-cast v5, Ljava/util/Collection;

    .line 46
    .line 47
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 48
    .line 49
    .line 50
    move-result v5

    .line 51
    move v6, v4

    .line 52
    :goto_1
    iget v7, v0, Lh2/cb;->i:I

    .line 53
    .line 54
    if-ge v6, v5, :cond_1

    .line 55
    .line 56
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v8

    .line 60
    check-cast v8, Lt3/p0;

    .line 61
    .line 62
    iget-object v9, v0, Lh2/cb;->h:Lt4/a;

    .line 63
    .line 64
    iget-wide v10, v9, Lt4/a;->a:J

    .line 65
    .line 66
    const/4 v15, 0x0

    .line 67
    const/16 v16, 0xb

    .line 68
    .line 69
    const/4 v12, 0x0

    .line 70
    const/4 v13, 0x0

    .line 71
    const/4 v14, 0x0

    .line 72
    invoke-static/range {v10 .. v16}, Lt4/a;->a(JIIIII)J

    .line 73
    .line 74
    .line 75
    move-result-wide v9

    .line 76
    invoke-interface {v8, v9, v10}, Lt3/p0;->L(J)Lt3/e1;

    .line 77
    .line 78
    .line 79
    move-result-object v8

    .line 80
    iget v9, v8, Lt3/e1;->e:I

    .line 81
    .line 82
    sub-int/2addr v7, v9

    .line 83
    invoke-static {v1, v8, v4, v7}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 84
    .line 85
    .line 86
    add-int/lit8 v6, v6, 0x1

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_1
    sget-object v2, Lh2/db;->f:Lh2/db;

    .line 90
    .line 91
    new-instance v5, Laa/p;

    .line 92
    .line 93
    const/16 v6, 0xb

    .line 94
    .line 95
    iget-object v8, v0, Lh2/cb;->j:Lt2/b;

    .line 96
    .line 97
    iget-object v9, v0, Lh2/cb;->k:Ljava/util/ArrayList;

    .line 98
    .line 99
    invoke-direct {v5, v6, v8, v9}, Laa/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    new-instance v6, Lt2/b;

    .line 103
    .line 104
    const/4 v8, 0x1

    .line 105
    const v9, 0x725db063

    .line 106
    .line 107
    .line 108
    invoke-direct {v6, v5, v8, v9}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 109
    .line 110
    .line 111
    invoke-interface {v3, v2, v6}, Lt3/p1;->C(Ljava/lang/Object;Lay0/n;)Ljava/util/List;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    move-object v3, v2

    .line 116
    check-cast v3, Ljava/util/Collection;

    .line 117
    .line 118
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 119
    .line 120
    .line 121
    move-result v3

    .line 122
    move v5, v4

    .line 123
    :goto_2
    if-ge v5, v3, :cond_5

    .line 124
    .line 125
    invoke-interface {v2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v6

    .line 129
    check-cast v6, Lt3/p0;

    .line 130
    .line 131
    iget v9, v0, Lh2/cb;->l:I

    .line 132
    .line 133
    if-ltz v9, :cond_2

    .line 134
    .line 135
    move v10, v8

    .line 136
    goto :goto_3

    .line 137
    :cond_2
    move v10, v4

    .line 138
    :goto_3
    if-ltz v7, :cond_3

    .line 139
    .line 140
    move v11, v8

    .line 141
    goto :goto_4

    .line 142
    :cond_3
    move v11, v4

    .line 143
    :goto_4
    and-int/2addr v10, v11

    .line 144
    if-nez v10, :cond_4

    .line 145
    .line 146
    const-string v10, "width and height must be >= 0"

    .line 147
    .line 148
    invoke-static {v10}, Lt4/i;->a(Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    :cond_4
    invoke-static {v9, v9, v7, v7}, Lt4/b;->h(IIII)J

    .line 152
    .line 153
    .line 154
    move-result-wide v9

    .line 155
    invoke-interface {v6, v9, v10}, Lt3/p0;->L(J)Lt3/e1;

    .line 156
    .line 157
    .line 158
    move-result-object v6

    .line 159
    invoke-static {v1, v6, v4, v4}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 160
    .line 161
    .line 162
    add-int/lit8 v5, v5, 0x1

    .line 163
    .line 164
    goto :goto_2

    .line 165
    :cond_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 166
    .line 167
    return-object v0
.end method
