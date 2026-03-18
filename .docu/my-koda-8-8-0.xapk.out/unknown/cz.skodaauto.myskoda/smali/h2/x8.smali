.class public final synthetic Lh2/x8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh2/a9;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Z

.field public final synthetic i:Lh2/u8;

.field public final synthetic j:Lay0/n;

.field public final synthetic k:Lay0/o;

.field public final synthetic l:F

.field public final synthetic m:F

.field public final synthetic n:I

.field public final synthetic o:I


# direct methods
.method public synthetic constructor <init>(Lh2/a9;Ljava/lang/Object;Lx2/s;ZLh2/u8;Lay0/n;Lay0/o;FFIII)V
    .locals 0

    .line 1
    iput p12, p0, Lh2/x8;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/x8;->e:Lh2/a9;

    .line 4
    .line 5
    iput-object p2, p0, Lh2/x8;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Lh2/x8;->g:Lx2/s;

    .line 8
    .line 9
    iput-boolean p4, p0, Lh2/x8;->h:Z

    .line 10
    .line 11
    iput-object p5, p0, Lh2/x8;->i:Lh2/u8;

    .line 12
    .line 13
    iput-object p6, p0, Lh2/x8;->j:Lay0/n;

    .line 14
    .line 15
    iput-object p7, p0, Lh2/x8;->k:Lay0/o;

    .line 16
    .line 17
    iput p8, p0, Lh2/x8;->l:F

    .line 18
    .line 19
    iput p9, p0, Lh2/x8;->m:F

    .line 20
    .line 21
    iput p10, p0, Lh2/x8;->n:I

    .line 22
    .line 23
    iput p11, p0, Lh2/x8;->o:I

    .line 24
    .line 25
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 26
    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lh2/x8;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/x8;->f:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v2, v0

    .line 9
    check-cast v2, Lh2/u7;

    .line 10
    .line 11
    move-object v10, p1

    .line 12
    check-cast v10, Ll2/o;

    .line 13
    .line 14
    check-cast p2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    iget p1, p0, Lh2/x8;->n:I

    .line 20
    .line 21
    or-int/lit8 p1, p1, 0x1

    .line 22
    .line 23
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 24
    .line 25
    .line 26
    move-result v11

    .line 27
    iget-object v1, p0, Lh2/x8;->e:Lh2/a9;

    .line 28
    .line 29
    iget-object v3, p0, Lh2/x8;->g:Lx2/s;

    .line 30
    .line 31
    iget-boolean v4, p0, Lh2/x8;->h:Z

    .line 32
    .line 33
    iget-object v5, p0, Lh2/x8;->i:Lh2/u8;

    .line 34
    .line 35
    iget-object v6, p0, Lh2/x8;->j:Lay0/n;

    .line 36
    .line 37
    iget-object v7, p0, Lh2/x8;->k:Lay0/o;

    .line 38
    .line 39
    iget v8, p0, Lh2/x8;->l:F

    .line 40
    .line 41
    iget v9, p0, Lh2/x8;->m:F

    .line 42
    .line 43
    iget v12, p0, Lh2/x8;->o:I

    .line 44
    .line 45
    invoke-virtual/range {v1 .. v12}, Lh2/a9;->a(Lh2/u7;Lx2/s;ZLh2/u8;Lay0/n;Lay0/o;FFLl2/o;II)V

    .line 46
    .line 47
    .line 48
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_0
    iget-object v0, p0, Lh2/x8;->f:Ljava/lang/Object;

    .line 52
    .line 53
    move-object v2, v0

    .line 54
    check-cast v2, Lh2/s9;

    .line 55
    .line 56
    move-object v10, p1

    .line 57
    check-cast v10, Ll2/o;

    .line 58
    .line 59
    check-cast p2, Ljava/lang/Integer;

    .line 60
    .line 61
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 62
    .line 63
    .line 64
    iget p1, p0, Lh2/x8;->n:I

    .line 65
    .line 66
    or-int/lit8 p1, p1, 0x1

    .line 67
    .line 68
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 69
    .line 70
    .line 71
    move-result v11

    .line 72
    iget p1, p0, Lh2/x8;->o:I

    .line 73
    .line 74
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 75
    .line 76
    .line 77
    move-result v12

    .line 78
    iget-object v1, p0, Lh2/x8;->e:Lh2/a9;

    .line 79
    .line 80
    iget-object v3, p0, Lh2/x8;->g:Lx2/s;

    .line 81
    .line 82
    iget-boolean v4, p0, Lh2/x8;->h:Z

    .line 83
    .line 84
    iget-object v5, p0, Lh2/x8;->i:Lh2/u8;

    .line 85
    .line 86
    iget-object v6, p0, Lh2/x8;->j:Lay0/n;

    .line 87
    .line 88
    iget-object v7, p0, Lh2/x8;->k:Lay0/o;

    .line 89
    .line 90
    iget v8, p0, Lh2/x8;->l:F

    .line 91
    .line 92
    iget v9, p0, Lh2/x8;->m:F

    .line 93
    .line 94
    invoke-virtual/range {v1 .. v12}, Lh2/a9;->c(Lh2/s9;Lx2/s;ZLh2/u8;Lay0/n;Lay0/o;FFLl2/o;II)V

    .line 95
    .line 96
    .line 97
    goto :goto_0

    .line 98
    :pswitch_1
    iget-object v0, p0, Lh2/x8;->f:Ljava/lang/Object;

    .line 99
    .line 100
    move-object v2, v0

    .line 101
    check-cast v2, Lh2/s9;

    .line 102
    .line 103
    move-object v10, p1

    .line 104
    check-cast v10, Ll2/o;

    .line 105
    .line 106
    check-cast p2, Ljava/lang/Integer;

    .line 107
    .line 108
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 109
    .line 110
    .line 111
    iget p1, p0, Lh2/x8;->n:I

    .line 112
    .line 113
    or-int/lit8 p1, p1, 0x1

    .line 114
    .line 115
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 116
    .line 117
    .line 118
    move-result v11

    .line 119
    iget-object v1, p0, Lh2/x8;->e:Lh2/a9;

    .line 120
    .line 121
    iget-object v3, p0, Lh2/x8;->g:Lx2/s;

    .line 122
    .line 123
    iget-boolean v4, p0, Lh2/x8;->h:Z

    .line 124
    .line 125
    iget-object v5, p0, Lh2/x8;->i:Lh2/u8;

    .line 126
    .line 127
    iget-object v6, p0, Lh2/x8;->j:Lay0/n;

    .line 128
    .line 129
    iget-object v7, p0, Lh2/x8;->k:Lay0/o;

    .line 130
    .line 131
    iget v8, p0, Lh2/x8;->l:F

    .line 132
    .line 133
    iget v9, p0, Lh2/x8;->m:F

    .line 134
    .line 135
    iget v12, p0, Lh2/x8;->o:I

    .line 136
    .line 137
    invoke-virtual/range {v1 .. v12}, Lh2/a9;->b(Lh2/s9;Lx2/s;ZLh2/u8;Lay0/n;Lay0/o;FFLl2/o;II)V

    .line 138
    .line 139
    .line 140
    goto :goto_0

    .line 141
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
