.class public Lcom/google/mlkit/common/internal/CommonComponentRegistrar;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/firebase/components/ComponentRegistrar;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final getComponents()Ljava/util/List;
    .locals 12

    .line 1
    sget-object v0, Lfv/i;->b:Lgs/b;

    .line 2
    .line 3
    const-class p0, Lgv/a;

    .line 4
    .line 5
    invoke-static {p0}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-class v1, Lfv/f;

    .line 10
    .line 11
    invoke-static {v1}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    invoke-virtual {p0, v2}, Lgs/a;->a(Lgs/k;)V

    .line 16
    .line 17
    .line 18
    new-instance v2, Lnm0/b;

    .line 19
    .line 20
    const/4 v3, 0x3

    .line 21
    invoke-direct {v2, v3}, Lnm0/b;-><init>(I)V

    .line 22
    .line 23
    .line 24
    iput-object v2, p0, Lgs/a;->f:Lgs/e;

    .line 25
    .line 26
    invoke-virtual {p0}, Lgs/a;->b()Lgs/b;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    const-class v2, Lfv/g;

    .line 31
    .line 32
    invoke-static {v2}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    new-instance v5, Lpy/a;

    .line 37
    .line 38
    invoke-direct {v5, v3}, Lpy/a;-><init>(I)V

    .line 39
    .line 40
    .line 41
    iput-object v5, v4, Lgs/a;->f:Lgs/e;

    .line 42
    .line 43
    invoke-virtual {v4}, Lgs/a;->b()Lgs/b;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    const-class v5, Lev/c;

    .line 48
    .line 49
    invoke-static {v5}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    new-instance v6, Lgs/k;

    .line 54
    .line 55
    const/4 v7, 0x2

    .line 56
    const/4 v8, 0x0

    .line 57
    const-class v9, Lev/b;

    .line 58
    .line 59
    invoke-direct {v6, v7, v8, v9}, Lgs/k;-><init>(IILjava/lang/Class;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v5, v6}, Lgs/a;->a(Lgs/k;)V

    .line 63
    .line 64
    .line 65
    new-instance v6, Lrb0/a;

    .line 66
    .line 67
    invoke-direct {v6, v3}, Lrb0/a;-><init>(I)V

    .line 68
    .line 69
    .line 70
    iput-object v6, v5, Lgs/a;->f:Lgs/e;

    .line 71
    .line 72
    invoke-virtual {v5}, Lgs/a;->b()Lgs/b;

    .line 73
    .line 74
    .line 75
    move-result-object v5

    .line 76
    const-class v6, Lfv/d;

    .line 77
    .line 78
    invoke-static {v6}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 79
    .line 80
    .line 81
    move-result-object v6

    .line 82
    new-instance v7, Lgs/k;

    .line 83
    .line 84
    const/4 v8, 0x1

    .line 85
    invoke-direct {v7, v8, v8, v2}, Lgs/k;-><init>(IILjava/lang/Class;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {v6, v7}, Lgs/a;->a(Lgs/k;)V

    .line 89
    .line 90
    .line 91
    new-instance v2, Lst/b;

    .line 92
    .line 93
    invoke-direct {v2, v3}, Lst/b;-><init>(I)V

    .line 94
    .line 95
    .line 96
    iput-object v2, v6, Lgs/a;->f:Lgs/e;

    .line 97
    .line 98
    invoke-virtual {v6}, Lgs/a;->b()Lgs/b;

    .line 99
    .line 100
    .line 101
    move-result-object v2

    .line 102
    const-class v6, Lfv/a;

    .line 103
    .line 104
    invoke-static {v6}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 105
    .line 106
    .line 107
    move-result-object v7

    .line 108
    new-instance v10, Lwe0/b;

    .line 109
    .line 110
    invoke-direct {v10, v3}, Lwe0/b;-><init>(I)V

    .line 111
    .line 112
    .line 113
    iput-object v10, v7, Lgs/a;->f:Lgs/e;

    .line 114
    .line 115
    invoke-virtual {v7}, Lgs/a;->b()Lgs/b;

    .line 116
    .line 117
    .line 118
    move-result-object v7

    .line 119
    const-class v10, Lfv/b;

    .line 120
    .line 121
    invoke-static {v10}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 122
    .line 123
    .line 124
    move-result-object v10

    .line 125
    invoke-static {v6}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 126
    .line 127
    .line 128
    move-result-object v6

    .line 129
    invoke-virtual {v10, v6}, Lgs/a;->a(Lgs/k;)V

    .line 130
    .line 131
    .line 132
    new-instance v6, Lwq/f;

    .line 133
    .line 134
    invoke-direct {v6, v3}, Lwq/f;-><init>(I)V

    .line 135
    .line 136
    .line 137
    iput-object v6, v10, Lgs/a;->f:Lgs/e;

    .line 138
    .line 139
    invoke-virtual {v10}, Lgs/a;->b()Lgs/b;

    .line 140
    .line 141
    .line 142
    move-result-object v6

    .line 143
    const-class v3, Ldv/a;

    .line 144
    .line 145
    invoke-static {v3}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 146
    .line 147
    .line 148
    move-result-object v10

    .line 149
    invoke-static {v1}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 150
    .line 151
    .line 152
    move-result-object v1

    .line 153
    invoke-virtual {v10, v1}, Lgs/a;->a(Lgs/k;)V

    .line 154
    .line 155
    .line 156
    new-instance v1, La61/a;

    .line 157
    .line 158
    const/4 v11, 0x4

    .line 159
    invoke-direct {v1, v11}, La61/a;-><init>(I)V

    .line 160
    .line 161
    .line 162
    iput-object v1, v10, Lgs/a;->f:Lgs/e;

    .line 163
    .line 164
    invoke-virtual {v10}, Lgs/a;->b()Lgs/b;

    .line 165
    .line 166
    .line 167
    move-result-object v1

    .line 168
    invoke-static {v9}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 169
    .line 170
    .line 171
    move-result-object v9

    .line 172
    iput v8, v9, Lgs/a;->e:I

    .line 173
    .line 174
    new-instance v10, Lgs/k;

    .line 175
    .line 176
    invoke-direct {v10, v8, v8, v3}, Lgs/k;-><init>(IILjava/lang/Class;)V

    .line 177
    .line 178
    .line 179
    invoke-virtual {v9, v10}, Lgs/a;->a(Lgs/k;)V

    .line 180
    .line 181
    .line 182
    new-instance v3, Ldv/a;

    .line 183
    .line 184
    invoke-direct {v3, v11}, Ldv/a;-><init>(I)V

    .line 185
    .line 186
    .line 187
    iput-object v3, v9, Lgs/a;->f:Lgs/e;

    .line 188
    .line 189
    invoke-virtual {v9}, Lgs/a;->b()Lgs/b;

    .line 190
    .line 191
    .line 192
    move-result-object v8

    .line 193
    sget-object v3, Lip/d;->e:Lip/b;

    .line 194
    .line 195
    move-object v3, v4

    .line 196
    move-object v4, v2

    .line 197
    move-object v2, v3

    .line 198
    move-object v3, v5

    .line 199
    move-object v5, v7

    .line 200
    move-object v7, v1

    .line 201
    move-object v1, p0

    .line 202
    filled-new-array/range {v0 .. v8}, [Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object p0

    .line 206
    const/16 v0, 0x9

    .line 207
    .line 208
    invoke-static {v0, p0}, Llp/ta;->a(I[Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    new-instance v1, Lip/g;

    .line 212
    .line 213
    invoke-direct {v1, p0, v0}, Lip/g;-><init>([Ljava/lang/Object;I)V

    .line 214
    .line 215
    .line 216
    return-object v1
.end method
