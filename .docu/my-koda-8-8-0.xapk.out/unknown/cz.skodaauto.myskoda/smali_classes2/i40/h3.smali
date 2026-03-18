.class public final synthetic Li40/h3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lh40/d4;

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Lay0/k;

.field public final synthetic k:Lay0/k;

.field public final synthetic l:Lay0/k;

.field public final synthetic m:Lay0/k;

.field public final synthetic n:Lay0/k;

.field public final synthetic o:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lh40/d4;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li40/h3;->d:Lh40/d4;

    .line 5
    .line 6
    iput-object p2, p0, Li40/h3;->e:Lay0/k;

    .line 7
    .line 8
    iput-object p3, p0, Li40/h3;->f:Lay0/k;

    .line 9
    .line 10
    iput-object p4, p0, Li40/h3;->g:Lay0/k;

    .line 11
    .line 12
    iput-object p5, p0, Li40/h3;->h:Lay0/k;

    .line 13
    .line 14
    iput-object p6, p0, Li40/h3;->i:Lay0/k;

    .line 15
    .line 16
    iput-object p7, p0, Li40/h3;->j:Lay0/k;

    .line 17
    .line 18
    iput-object p8, p0, Li40/h3;->k:Lay0/k;

    .line 19
    .line 20
    iput-object p9, p0, Li40/h3;->l:Lay0/k;

    .line 21
    .line 22
    iput-object p10, p0, Li40/h3;->m:Lay0/k;

    .line 23
    .line 24
    iput-object p11, p0, Li40/h3;->n:Lay0/k;

    .line 25
    .line 26
    iput-object p12, p0, Li40/h3;->o:Lay0/k;

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    check-cast p1, Lm1/f;

    .line 2
    .line 3
    const-string v0, "$this$LazyColumn"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Li40/h3;->d:Lh40/d4;

    .line 9
    .line 10
    iget-boolean v1, v0, Lh40/d4;->b:Z

    .line 11
    .line 12
    const/4 v2, 0x3

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    iget-boolean v1, v0, Lh40/d4;->c:Z

    .line 16
    .line 17
    if-nez v1, :cond_0

    .line 18
    .line 19
    iget-boolean v1, v0, Lh40/d4;->o:Z

    .line 20
    .line 21
    if-nez v1, :cond_0

    .line 22
    .line 23
    sget-object p0, Li40/q;->G:Lt2/b;

    .line 24
    .line 25
    invoke-static {p1, p0, v2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 26
    .line 27
    .line 28
    goto/16 :goto_0

    .line 29
    .line 30
    :cond_0
    iget v1, v0, Lh40/d4;->a:I

    .line 31
    .line 32
    new-instance v3, Ldl0/a;

    .line 33
    .line 34
    const/4 v4, 0x3

    .line 35
    invoke-direct {v3, v1, v4}, Ldl0/a;-><init>(II)V

    .line 36
    .line 37
    .line 38
    new-instance v1, Lt2/b;

    .line 39
    .line 40
    const/4 v4, 0x1

    .line 41
    const v5, -0x576898b3

    .line 42
    .line 43
    .line 44
    invoke-direct {v1, v3, v4, v5}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 45
    .line 46
    .line 47
    invoke-static {p1, v1, v2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 48
    .line 49
    .line 50
    iget-object v7, v0, Lh40/d4;->e:Ljava/util/List;

    .line 51
    .line 52
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    new-instance v3, Lak/p;

    .line 57
    .line 58
    const/16 v5, 0x16

    .line 59
    .line 60
    invoke-direct {v3, v7, v5}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 61
    .line 62
    .line 63
    new-instance v6, Li40/w2;

    .line 64
    .line 65
    const/4 v11, 0x1

    .line 66
    iget-object v9, p0, Li40/h3;->h:Lay0/k;

    .line 67
    .line 68
    iget-object v10, p0, Li40/h3;->l:Lay0/k;

    .line 69
    .line 70
    move-object v8, v7

    .line 71
    invoke-direct/range {v6 .. v11}, Li40/w2;-><init>(Ljava/util/List;Ljava/util/List;Lay0/k;Lay0/k;I)V

    .line 72
    .line 73
    .line 74
    new-instance v5, Lt2/b;

    .line 75
    .line 76
    const v7, 0x799532c4

    .line 77
    .line 78
    .line 79
    invoke-direct {v5, v6, v4, v7}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 80
    .line 81
    .line 82
    const/4 v6, 0x0

    .line 83
    invoke-virtual {p1, v1, v6, v3, v5}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 84
    .line 85
    .line 86
    new-instance v1, Li40/n2;

    .line 87
    .line 88
    const/4 v3, 0x1

    .line 89
    iget-object v5, p0, Li40/h3;->f:Lay0/k;

    .line 90
    .line 91
    iget-object v6, p0, Li40/h3;->e:Lay0/k;

    .line 92
    .line 93
    invoke-direct {v1, v0, v5, v6, v3}, Li40/n2;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 94
    .line 95
    .line 96
    new-instance v3, Lt2/b;

    .line 97
    .line 98
    const v5, 0x45465dda

    .line 99
    .line 100
    .line 101
    invoke-direct {v3, v1, v4, v5}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 102
    .line 103
    .line 104
    invoke-static {p1, v3, v2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v0}, Lh40/d4;->d()Ljava/util/List;

    .line 108
    .line 109
    .line 110
    move-result-object v1

    .line 111
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    if-eqz v1, :cond_1

    .line 116
    .line 117
    sget-object p0, Li40/q;->H:Lt2/b;

    .line 118
    .line 119
    invoke-static {p1, p0, v2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 120
    .line 121
    .line 122
    goto :goto_0

    .line 123
    :cond_1
    invoke-virtual {v0}, Lh40/d4;->d()Ljava/util/List;

    .line 124
    .line 125
    .line 126
    move-result-object v6

    .line 127
    new-instance v0, Li40/r2;

    .line 128
    .line 129
    const/16 v1, 0xd

    .line 130
    .line 131
    invoke-direct {v0, v1}, Li40/r2;-><init>(I)V

    .line 132
    .line 133
    .line 134
    invoke-interface {v6}, Ljava/util/List;->size()I

    .line 135
    .line 136
    .line 137
    move-result v1

    .line 138
    new-instance v2, Lc41/g;

    .line 139
    .line 140
    const/16 v3, 0xb

    .line 141
    .line 142
    invoke-direct {v2, v3, v0, v6}, Lc41/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    new-instance v0, Li40/j3;

    .line 146
    .line 147
    const/4 v3, 0x0

    .line 148
    invoke-direct {v0, v6, v3}, Li40/j3;-><init>(Ljava/util/List;I)V

    .line 149
    .line 150
    .line 151
    new-instance v5, Lh2/c3;

    .line 152
    .line 153
    iget-object v7, p0, Li40/h3;->g:Lay0/k;

    .line 154
    .line 155
    iget-object v8, p0, Li40/h3;->m:Lay0/k;

    .line 156
    .line 157
    iget-object v9, p0, Li40/h3;->i:Lay0/k;

    .line 158
    .line 159
    iget-object v10, p0, Li40/h3;->j:Lay0/k;

    .line 160
    .line 161
    iget-object v11, p0, Li40/h3;->k:Lay0/k;

    .line 162
    .line 163
    iget-object v12, p0, Li40/h3;->o:Lay0/k;

    .line 164
    .line 165
    iget-object v13, p0, Li40/h3;->n:Lay0/k;

    .line 166
    .line 167
    invoke-direct/range {v5 .. v13}, Lh2/c3;-><init>(Ljava/util/List;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;)V

    .line 168
    .line 169
    .line 170
    new-instance p0, Lt2/b;

    .line 171
    .line 172
    const v3, 0x2fd4df92

    .line 173
    .line 174
    .line 175
    invoke-direct {p0, v5, v4, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {p1, v1, v2, v0, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 179
    .line 180
    .line 181
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 182
    .line 183
    return-object p0
.end method
