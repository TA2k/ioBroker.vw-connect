.class public final synthetic La71/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Li91/s2;Lay0/k;Lay0/k;Ll2/b1;Li91/r2;ZLiv0/f;I)V
    .locals 0

    .line 1
    const/4 p8, 0x1

    iput p8, p0, La71/k0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La71/k0;->f:Ljava/lang/Object;

    iput-object p2, p0, La71/k0;->g:Ljava/lang/Object;

    iput-object p3, p0, La71/k0;->h:Ljava/lang/Object;

    iput-object p4, p0, La71/k0;->i:Ljava/lang/Object;

    iput-object p5, p0, La71/k0;->j:Ljava/lang/Object;

    iput-boolean p6, p0, La71/k0;->e:Z

    iput-object p7, p0, La71/k0;->k:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/a;Lay0/a;ZI)V
    .locals 0

    .line 2
    const/4 p8, 0x2

    iput p8, p0, La71/k0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La71/k0;->f:Ljava/lang/Object;

    iput-object p2, p0, La71/k0;->g:Ljava/lang/Object;

    iput-object p3, p0, La71/k0;->h:Ljava/lang/Object;

    iput-object p4, p0, La71/k0;->i:Ljava/lang/Object;

    iput-object p5, p0, La71/k0;->j:Ljava/lang/Object;

    iput-object p6, p0, La71/k0;->k:Ljava/lang/Object;

    iput-boolean p7, p0, La71/k0;->e:Z

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Lx61/b;Ls71/h;Lt71/d;ZLay0/a;Lt2/b;I)V
    .locals 0

    .line 3
    const/4 p8, 0x0

    iput p8, p0, La71/k0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La71/k0;->f:Ljava/lang/Object;

    iput-object p2, p0, La71/k0;->g:Ljava/lang/Object;

    iput-object p3, p0, La71/k0;->h:Ljava/lang/Object;

    iput-object p4, p0, La71/k0;->i:Ljava/lang/Object;

    iput-boolean p5, p0, La71/k0;->e:Z

    iput-object p6, p0, La71/k0;->j:Ljava/lang/Object;

    iput-object p7, p0, La71/k0;->k:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, La71/k0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, La71/k0;->f:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Lx2/s;

    .line 10
    .line 11
    iget-object v0, p0, La71/k0;->g:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    check-cast v2, Ljava/lang/String;

    .line 15
    .line 16
    iget-object v0, p0, La71/k0;->h:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v3, v0

    .line 19
    check-cast v3, Ljava/lang/String;

    .line 20
    .line 21
    iget-object v0, p0, La71/k0;->i:Ljava/lang/Object;

    .line 22
    .line 23
    move-object v4, v0

    .line 24
    check-cast v4, Ljava/lang/String;

    .line 25
    .line 26
    iget-object v0, p0, La71/k0;->j:Ljava/lang/Object;

    .line 27
    .line 28
    move-object v5, v0

    .line 29
    check-cast v5, Lay0/a;

    .line 30
    .line 31
    iget-object v0, p0, La71/k0;->k:Ljava/lang/Object;

    .line 32
    .line 33
    move-object v6, v0

    .line 34
    check-cast v6, Lay0/a;

    .line 35
    .line 36
    move-object v8, p1

    .line 37
    check-cast v8, Ll2/o;

    .line 38
    .line 39
    check-cast p2, Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    const/4 p1, 0x1

    .line 45
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 46
    .line 47
    .line 48
    move-result v9

    .line 49
    iget-boolean v7, p0, La71/k0;->e:Z

    .line 50
    .line 51
    invoke-static/range {v1 .. v9}, Lz61/a;->g(Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/a;Lay0/a;ZLl2/o;I)V

    .line 52
    .line 53
    .line 54
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_0
    iget-object v0, p0, La71/k0;->f:Ljava/lang/Object;

    .line 58
    .line 59
    move-object v1, v0

    .line 60
    check-cast v1, Li91/s2;

    .line 61
    .line 62
    iget-object v0, p0, La71/k0;->g:Ljava/lang/Object;

    .line 63
    .line 64
    move-object v2, v0

    .line 65
    check-cast v2, Lay0/k;

    .line 66
    .line 67
    iget-object v0, p0, La71/k0;->h:Ljava/lang/Object;

    .line 68
    .line 69
    move-object v3, v0

    .line 70
    check-cast v3, Lay0/k;

    .line 71
    .line 72
    iget-object v0, p0, La71/k0;->i:Ljava/lang/Object;

    .line 73
    .line 74
    move-object v4, v0

    .line 75
    check-cast v4, Ll2/b1;

    .line 76
    .line 77
    iget-object v0, p0, La71/k0;->j:Ljava/lang/Object;

    .line 78
    .line 79
    move-object v5, v0

    .line 80
    check-cast v5, Li91/r2;

    .line 81
    .line 82
    iget-object v0, p0, La71/k0;->k:Ljava/lang/Object;

    .line 83
    .line 84
    move-object v7, v0

    .line 85
    check-cast v7, Liv0/f;

    .line 86
    .line 87
    move-object v8, p1

    .line 88
    check-cast v8, Ll2/o;

    .line 89
    .line 90
    check-cast p2, Ljava/lang/Integer;

    .line 91
    .line 92
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 93
    .line 94
    .line 95
    const p1, 0x8c01

    .line 96
    .line 97
    .line 98
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 99
    .line 100
    .line 101
    move-result v9

    .line 102
    iget-boolean v6, p0, La71/k0;->e:Z

    .line 103
    .line 104
    invoke-static/range {v1 .. v9}, Lkv0/i;->e(Li91/s2;Lay0/k;Lay0/k;Ll2/b1;Li91/r2;ZLiv0/f;Ll2/o;I)V

    .line 105
    .line 106
    .line 107
    goto :goto_0

    .line 108
    :pswitch_1
    iget-object v0, p0, La71/k0;->f:Ljava/lang/Object;

    .line 109
    .line 110
    move-object v1, v0

    .line 111
    check-cast v1, Lx2/s;

    .line 112
    .line 113
    iget-object v0, p0, La71/k0;->g:Ljava/lang/Object;

    .line 114
    .line 115
    move-object v2, v0

    .line 116
    check-cast v2, Lx61/b;

    .line 117
    .line 118
    iget-object v0, p0, La71/k0;->h:Ljava/lang/Object;

    .line 119
    .line 120
    move-object v3, v0

    .line 121
    check-cast v3, Ls71/h;

    .line 122
    .line 123
    iget-object v0, p0, La71/k0;->i:Ljava/lang/Object;

    .line 124
    .line 125
    move-object v4, v0

    .line 126
    check-cast v4, Lt71/d;

    .line 127
    .line 128
    iget-object v0, p0, La71/k0;->j:Ljava/lang/Object;

    .line 129
    .line 130
    move-object v6, v0

    .line 131
    check-cast v6, Lay0/a;

    .line 132
    .line 133
    iget-object v0, p0, La71/k0;->k:Ljava/lang/Object;

    .line 134
    .line 135
    move-object v7, v0

    .line 136
    check-cast v7, Lt2/b;

    .line 137
    .line 138
    move-object v8, p1

    .line 139
    check-cast v8, Ll2/o;

    .line 140
    .line 141
    check-cast p2, Ljava/lang/Integer;

    .line 142
    .line 143
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 144
    .line 145
    .line 146
    const p1, 0x180001

    .line 147
    .line 148
    .line 149
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 150
    .line 151
    .line 152
    move-result v9

    .line 153
    iget-boolean v5, p0, La71/k0;->e:Z

    .line 154
    .line 155
    invoke-static/range {v1 .. v9}, La71/s0;->e(Lx2/s;Lx61/b;Ls71/h;Lt71/d;ZLay0/a;Lt2/b;Ll2/o;I)V

    .line 156
    .line 157
    .line 158
    goto :goto_0

    .line 159
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
