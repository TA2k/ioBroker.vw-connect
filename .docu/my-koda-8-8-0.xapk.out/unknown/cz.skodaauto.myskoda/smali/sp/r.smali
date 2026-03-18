.class public final Lsp/r;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lsp/r;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:Ljava/util/List;

.field public e:F

.field public f:I

.field public g:F

.field public h:Z

.field public i:Z

.field public j:Z

.field public k:Lsp/d;

.field public l:Lsp/d;

.field public m:I

.field public n:Ljava/util/List;

.field public final o:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lpp/h;

    .line 2
    .line 3
    const/16 v1, 0x17

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lpp/h;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lsp/r;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/high16 v0, 0x41200000    # 10.0f

    .line 2
    iput v0, p0, Lsp/r;->e:F

    const/high16 v0, -0x1000000

    iput v0, p0, Lsp/r;->f:I

    const/4 v0, 0x0

    iput v0, p0, Lsp/r;->g:F

    const/4 v0, 0x1

    iput-boolean v0, p0, Lsp/r;->h:Z

    const/4 v0, 0x0

    iput-boolean v0, p0, Lsp/r;->i:Z

    iput-boolean v0, p0, Lsp/r;->j:Z

    .line 3
    new-instance v1, Lsp/c;

    invoke-direct {v1}, Lsp/c;-><init>()V

    iput-object v1, p0, Lsp/r;->k:Lsp/d;

    new-instance v1, Lsp/c;

    .line 4
    invoke-direct {v1}, Lsp/c;-><init>()V

    iput-object v1, p0, Lsp/r;->l:Lsp/d;

    iput v0, p0, Lsp/r;->m:I

    const/4 v0, 0x0

    iput-object v0, p0, Lsp/r;->n:Ljava/util/List;

    new-instance v0, Ljava/util/ArrayList;

    .line 5
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lsp/r;->o:Ljava/util/List;

    new-instance v0, Ljava/util/ArrayList;

    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lsp/r;->d:Ljava/util/List;

    return-void
.end method

.method public constructor <init>(Ljava/util/ArrayList;FIFZZZLsp/d;Lsp/d;ILjava/util/ArrayList;Ljava/util/ArrayList;)V
    .locals 2

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/high16 v0, 0x41200000    # 10.0f

    .line 8
    iput v0, p0, Lsp/r;->e:F

    const/high16 v0, -0x1000000

    iput v0, p0, Lsp/r;->f:I

    const/4 v0, 0x0

    iput v0, p0, Lsp/r;->g:F

    const/4 v0, 0x1

    iput-boolean v0, p0, Lsp/r;->h:Z

    const/4 v0, 0x0

    iput-boolean v0, p0, Lsp/r;->i:Z

    iput-boolean v0, p0, Lsp/r;->j:Z

    .line 9
    new-instance v1, Lsp/c;

    invoke-direct {v1}, Lsp/c;-><init>()V

    iput-object v1, p0, Lsp/r;->k:Lsp/d;

    new-instance v1, Lsp/c;

    .line 10
    invoke-direct {v1}, Lsp/c;-><init>()V

    iput-object v1, p0, Lsp/r;->l:Lsp/d;

    iput v0, p0, Lsp/r;->m:I

    const/4 v0, 0x0

    iput-object v0, p0, Lsp/r;->n:Ljava/util/List;

    new-instance v0, Ljava/util/ArrayList;

    .line 11
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lsp/r;->o:Ljava/util/List;

    iput-object p1, p0, Lsp/r;->d:Ljava/util/List;

    iput p2, p0, Lsp/r;->e:F

    iput p3, p0, Lsp/r;->f:I

    iput p4, p0, Lsp/r;->g:F

    iput-boolean p5, p0, Lsp/r;->h:Z

    iput-boolean p6, p0, Lsp/r;->i:Z

    iput-boolean p7, p0, Lsp/r;->j:Z

    if-eqz p8, :cond_0

    iput-object p8, p0, Lsp/r;->k:Lsp/d;

    :cond_0
    if-eqz p9, :cond_1

    iput-object p9, p0, Lsp/r;->l:Lsp/d;

    :cond_1
    iput p10, p0, Lsp/r;->m:I

    iput-object p11, p0, Lsp/r;->n:Ljava/util/List;

    if-eqz p12, :cond_2

    iput-object p12, p0, Lsp/r;->o:Ljava/util/List;

    :cond_2
    return-void
.end method


# virtual methods
.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p2

    .line 6
    .line 7
    const/16 v3, 0x4f45

    .line 8
    .line 9
    invoke-static {v1, v3}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    const/4 v4, 0x2

    .line 14
    iget-object v5, v0, Lsp/r;->d:Ljava/util/List;

    .line 15
    .line 16
    invoke-static {v1, v4, v5}, Ljp/dc;->r(Landroid/os/Parcel;ILjava/util/List;)V

    .line 17
    .line 18
    .line 19
    iget v4, v0, Lsp/r;->e:F

    .line 20
    .line 21
    const/4 v5, 0x3

    .line 22
    const/4 v6, 0x4

    .line 23
    invoke-static {v1, v5, v6}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v1, v4}, Landroid/os/Parcel;->writeFloat(F)V

    .line 27
    .line 28
    .line 29
    iget v4, v0, Lsp/r;->f:I

    .line 30
    .line 31
    invoke-static {v1, v6, v6}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v1, v4}, Landroid/os/Parcel;->writeInt(I)V

    .line 35
    .line 36
    .line 37
    iget v4, v0, Lsp/r;->g:F

    .line 38
    .line 39
    const/4 v5, 0x5

    .line 40
    invoke-static {v1, v5, v6}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v1, v4}, Landroid/os/Parcel;->writeFloat(F)V

    .line 44
    .line 45
    .line 46
    iget-boolean v4, v0, Lsp/r;->h:Z

    .line 47
    .line 48
    const/4 v5, 0x6

    .line 49
    invoke-static {v1, v5, v6}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v1, v4}, Landroid/os/Parcel;->writeInt(I)V

    .line 53
    .line 54
    .line 55
    iget-boolean v4, v0, Lsp/r;->i:Z

    .line 56
    .line 57
    const/4 v5, 0x7

    .line 58
    invoke-static {v1, v5, v6}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v1, v4}, Landroid/os/Parcel;->writeInt(I)V

    .line 62
    .line 63
    .line 64
    iget-boolean v4, v0, Lsp/r;->j:Z

    .line 65
    .line 66
    const/16 v5, 0x8

    .line 67
    .line 68
    invoke-static {v1, v5, v6}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v1, v4}, Landroid/os/Parcel;->writeInt(I)V

    .line 72
    .line 73
    .line 74
    iget-object v4, v0, Lsp/r;->k:Lsp/d;

    .line 75
    .line 76
    invoke-virtual {v4}, Lsp/d;->x0()Lsp/d;

    .line 77
    .line 78
    .line 79
    move-result-object v4

    .line 80
    const/16 v5, 0x9

    .line 81
    .line 82
    invoke-static {v1, v5, v4, v2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 83
    .line 84
    .line 85
    iget-object v4, v0, Lsp/r;->l:Lsp/d;

    .line 86
    .line 87
    invoke-virtual {v4}, Lsp/d;->x0()Lsp/d;

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    const/16 v5, 0xa

    .line 92
    .line 93
    invoke-static {v1, v5, v4, v2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 94
    .line 95
    .line 96
    iget v2, v0, Lsp/r;->m:I

    .line 97
    .line 98
    const/16 v4, 0xb

    .line 99
    .line 100
    invoke-static {v1, v4, v6}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {v1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 104
    .line 105
    .line 106
    const/16 v2, 0xc

    .line 107
    .line 108
    iget-object v4, v0, Lsp/r;->n:Ljava/util/List;

    .line 109
    .line 110
    invoke-static {v1, v2, v4}, Ljp/dc;->r(Landroid/os/Parcel;ILjava/util/List;)V

    .line 111
    .line 112
    .line 113
    new-instance v2, Ljava/util/ArrayList;

    .line 114
    .line 115
    iget-object v4, v0, Lsp/r;->o:Ljava/util/List;

    .line 116
    .line 117
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 118
    .line 119
    .line 120
    move-result v5

    .line 121
    invoke-direct {v2, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 122
    .line 123
    .line 124
    invoke-interface {v4}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 125
    .line 126
    .line 127
    move-result-object v4

    .line 128
    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 129
    .line 130
    .line 131
    move-result v5

    .line 132
    if-eqz v5, :cond_0

    .line 133
    .line 134
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v5

    .line 138
    check-cast v5, Lsp/u;

    .line 139
    .line 140
    new-instance v6, Lsp/u;

    .line 141
    .line 142
    iget-object v7, v5, Lsp/u;->d:Lsp/t;

    .line 143
    .line 144
    iget v8, v7, Lsp/t;->d:F

    .line 145
    .line 146
    iget v8, v7, Lsp/t;->f:I

    .line 147
    .line 148
    iget v9, v7, Lsp/t;->e:I

    .line 149
    .line 150
    new-instance v10, Landroid/util/Pair;

    .line 151
    .line 152
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 153
    .line 154
    .line 155
    move-result-object v9

    .line 156
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 157
    .line 158
    .line 159
    move-result-object v8

    .line 160
    invoke-direct {v10, v9, v8}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    iget-object v8, v10, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 164
    .line 165
    check-cast v8, Ljava/lang/Integer;

    .line 166
    .line 167
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 168
    .line 169
    .line 170
    move-result v13

    .line 171
    iget-object v8, v10, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 172
    .line 173
    check-cast v8, Ljava/lang/Integer;

    .line 174
    .line 175
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 176
    .line 177
    .line 178
    move-result v14

    .line 179
    iget-object v7, v7, Lsp/t;->h:Lsp/s;

    .line 180
    .line 181
    iget v12, v0, Lsp/r;->e:F

    .line 182
    .line 183
    iget-boolean v15, v0, Lsp/r;->h:Z

    .line 184
    .line 185
    new-instance v11, Lsp/t;

    .line 186
    .line 187
    move-object/from16 v16, v7

    .line 188
    .line 189
    invoke-direct/range {v11 .. v16}, Lsp/t;-><init>(FIIZLsp/s;)V

    .line 190
    .line 191
    .line 192
    iget-wide v7, v5, Lsp/u;->e:D

    .line 193
    .line 194
    invoke-direct {v6, v11, v7, v8}, Lsp/u;-><init>(Lsp/t;D)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    goto :goto_0

    .line 201
    :cond_0
    const/16 v0, 0xd

    .line 202
    .line 203
    invoke-static {v1, v0, v2}, Ljp/dc;->r(Landroid/os/Parcel;ILjava/util/List;)V

    .line 204
    .line 205
    .line 206
    invoke-static {v1, v3}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 207
    .line 208
    .line 209
    return-void
.end method
