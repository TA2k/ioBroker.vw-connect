.class public final synthetic Luu/h1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Luu/x;

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ll2/r;

.field public final synthetic g:Luu/l1;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Lay0/k;

.field public final synthetic k:Lay0/k;

.field public final synthetic l:Ljava/lang/String;

.field public final synthetic m:F

.field public final synthetic n:J

.field public final synthetic o:Lsp/b;

.field public final synthetic p:J

.field public final synthetic q:Z

.field public final synthetic r:F


# direct methods
.method public synthetic constructor <init>(Luu/x;Ljava/lang/Object;Ll2/r;Luu/l1;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Ljava/lang/String;FJLsp/b;JZF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luu/h1;->d:Luu/x;

    .line 5
    .line 6
    iput-object p2, p0, Luu/h1;->e:Ljava/lang/Object;

    .line 7
    .line 8
    iput-object p3, p0, Luu/h1;->f:Ll2/r;

    .line 9
    .line 10
    iput-object p4, p0, Luu/h1;->g:Luu/l1;

    .line 11
    .line 12
    iput-object p5, p0, Luu/h1;->h:Lay0/k;

    .line 13
    .line 14
    iput-object p6, p0, Luu/h1;->i:Lay0/k;

    .line 15
    .line 16
    iput-object p7, p0, Luu/h1;->j:Lay0/k;

    .line 17
    .line 18
    iput-object p8, p0, Luu/h1;->k:Lay0/k;

    .line 19
    .line 20
    iput-object p9, p0, Luu/h1;->l:Ljava/lang/String;

    .line 21
    .line 22
    iput p10, p0, Luu/h1;->m:F

    .line 23
    .line 24
    iput-wide p11, p0, Luu/h1;->n:J

    .line 25
    .line 26
    iput-object p13, p0, Luu/h1;->o:Lsp/b;

    .line 27
    .line 28
    iput-wide p14, p0, Luu/h1;->p:J

    .line 29
    .line 30
    move/from16 p1, p16

    .line 31
    .line 32
    iput-boolean p1, p0, Luu/h1;->q:Z

    .line 33
    .line 34
    move/from16 p1, p17

    .line 35
    .line 36
    iput p1, p0, Luu/h1;->r:F

    .line 37
    .line 38
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 13

    .line 1
    iget-object v0, p0, Luu/h1;->d:Luu/x;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-object v0, v0, Luu/x;->h:Lqp/g;

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    new-instance v1, Lsp/l;

    .line 10
    .line 11
    invoke-direct {v1}, Lsp/l;-><init>()V

    .line 12
    .line 13
    .line 14
    iget-object v2, p0, Luu/h1;->l:Ljava/lang/String;

    .line 15
    .line 16
    iput-object v2, v1, Lsp/l;->u:Ljava/lang/String;

    .line 17
    .line 18
    iget v2, p0, Luu/h1;->m:F

    .line 19
    .line 20
    iput v2, v1, Lsp/l;->p:F

    .line 21
    .line 22
    iget-wide v2, p0, Luu/h1;->n:J

    .line 23
    .line 24
    const/16 v4, 0x20

    .line 25
    .line 26
    shr-long v5, v2, v4

    .line 27
    .line 28
    long-to-int v5, v5

    .line 29
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 30
    .line 31
    .line 32
    move-result v5

    .line 33
    const-wide v6, 0xffffffffL

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    and-long/2addr v2, v6

    .line 39
    long-to-int v2, v2

    .line 40
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    iput v5, v1, Lsp/l;->h:F

    .line 45
    .line 46
    iput v2, v1, Lsp/l;->i:F

    .line 47
    .line 48
    const/4 v2, 0x0

    .line 49
    iput-boolean v2, v1, Lsp/l;->j:Z

    .line 50
    .line 51
    iput-boolean v2, v1, Lsp/l;->l:Z

    .line 52
    .line 53
    iget-object v2, p0, Luu/h1;->o:Lsp/b;

    .line 54
    .line 55
    iput-object v2, v1, Lsp/l;->g:Lsp/b;

    .line 56
    .line 57
    iget-wide v2, p0, Luu/h1;->p:J

    .line 58
    .line 59
    shr-long v4, v2, v4

    .line 60
    .line 61
    long-to-int v4, v4

    .line 62
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    and-long/2addr v2, v6

    .line 67
    long-to-int v2, v2

    .line 68
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    iput v4, v1, Lsp/l;->n:F

    .line 73
    .line 74
    iput v2, v1, Lsp/l;->o:F

    .line 75
    .line 76
    iget-object v8, p0, Luu/h1;->g:Luu/l1;

    .line 77
    .line 78
    iget-object v2, v8, Luu/l1;->a:Ll2/j1;

    .line 79
    .line 80
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    check-cast v2, Lcom/google/android/gms/maps/model/LatLng;

    .line 85
    .line 86
    if-eqz v2, :cond_0

    .line 87
    .line 88
    iput-object v2, v1, Lsp/l;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 89
    .line 90
    const/4 v2, 0x0

    .line 91
    iput v2, v1, Lsp/l;->m:F

    .line 92
    .line 93
    const/4 v2, 0x0

    .line 94
    iput-object v2, v1, Lsp/l;->f:Ljava/lang/String;

    .line 95
    .line 96
    iput-object v2, v1, Lsp/l;->e:Ljava/lang/String;

    .line 97
    .line 98
    iget-boolean v2, p0, Luu/h1;->q:Z

    .line 99
    .line 100
    iput-boolean v2, v1, Lsp/l;->k:Z

    .line 101
    .line 102
    iget v2, p0, Luu/h1;->r:F

    .line 103
    .line 104
    iput v2, v1, Lsp/l;->q:F

    .line 105
    .line 106
    invoke-virtual {v0, v1}, Lqp/g;->a(Lsp/l;)Lsp/k;

    .line 107
    .line 108
    .line 109
    move-result-object v7

    .line 110
    if-eqz v7, :cond_1

    .line 111
    .line 112
    iget-object v0, p0, Luu/h1;->e:Ljava/lang/Object;

    .line 113
    .line 114
    invoke-virtual {v7, v0}, Lsp/k;->f(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    new-instance v5, Luu/k1;

    .line 118
    .line 119
    iget-object v6, p0, Luu/h1;->f:Ll2/r;

    .line 120
    .line 121
    iget-object v9, p0, Luu/h1;->h:Lay0/k;

    .line 122
    .line 123
    iget-object v10, p0, Luu/h1;->i:Lay0/k;

    .line 124
    .line 125
    iget-object v11, p0, Luu/h1;->j:Lay0/k;

    .line 126
    .line 127
    iget-object v12, p0, Luu/h1;->k:Lay0/k;

    .line 128
    .line 129
    invoke-direct/range {v5 .. v12}, Luu/k1;-><init>(Ll2/r;Lsp/k;Luu/l1;Lay0/k;Lay0/k;Lay0/k;Lay0/k;)V

    .line 130
    .line 131
    .line 132
    return-object v5

    .line 133
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 134
    .line 135
    const-string v0, "latlng cannot be null - a position is required."

    .line 136
    .line 137
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    throw p0

    .line 141
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 142
    .line 143
    const-string v0, "Error adding marker"

    .line 144
    .line 145
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    throw p0
.end method
