.class public final synthetic Ldk/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)V
    .locals 0

    .line 1
    const/4 p1, 0x0

    iput p1, p0, Ldk/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p6, p0, Ldk/a;->e:Z

    iput-object p2, p0, Ldk/a;->g:Ljava/lang/Object;

    iput-boolean p7, p0, Ldk/a;->f:Z

    iput-object p3, p0, Ldk/a;->h:Ljava/lang/Object;

    iput-object p4, p0, Ldk/a;->i:Ljava/lang/Object;

    iput-object p5, p0, Ldk/a;->j:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lh2/hb;ZZLi1/l;Lh2/eb;Le3/n0;I)V
    .locals 0

    .line 2
    const/4 p7, 0x1

    iput p7, p0, Ldk/a;->d:I

    sget-object p7, Lh2/hb;->a:Lh2/hb;

    sget-object p7, Lh2/hb;->a:Lh2/hb;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ldk/a;->g:Ljava/lang/Object;

    iput-boolean p2, p0, Ldk/a;->e:Z

    iput-boolean p3, p0, Ldk/a;->f:Z

    iput-object p4, p0, Ldk/a;->h:Ljava/lang/Object;

    iput-object p5, p0, Ldk/a;->i:Ljava/lang/Object;

    iput-object p6, p0, Ldk/a;->j:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;ZZLay0/a;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 3
    const/4 p7, 0x2

    iput p7, p0, Ldk/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ldk/a;->g:Ljava/lang/Object;

    iput-boolean p2, p0, Ldk/a;->e:Z

    iput-boolean p3, p0, Ldk/a;->f:Z

    iput-object p4, p0, Ldk/a;->h:Ljava/lang/Object;

    iput-object p5, p0, Ldk/a;->i:Ljava/lang/Object;

    iput-object p6, p0, Ldk/a;->j:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ldk/a;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v3, v0, Ldk/a;->j:Ljava/lang/Object;

    .line 8
    .line 9
    iget-object v4, v0, Ldk/a;->i:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object v5, v0, Ldk/a;->h:Ljava/lang/Object;

    .line 12
    .line 13
    iget-object v6, v0, Ldk/a;->g:Ljava/lang/Object;

    .line 14
    .line 15
    packed-switch v1, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    move-object v7, v6

    .line 19
    check-cast v7, Lx2/s;

    .line 20
    .line 21
    move-object v10, v5

    .line 22
    check-cast v10, Lay0/a;

    .line 23
    .line 24
    move-object v11, v4

    .line 25
    check-cast v11, Lay0/a;

    .line 26
    .line 27
    move-object v12, v3

    .line 28
    check-cast v12, Lay0/a;

    .line 29
    .line 30
    move-object/from16 v13, p1

    .line 31
    .line 32
    check-cast v13, Ll2/o;

    .line 33
    .line 34
    move-object/from16 v1, p2

    .line 35
    .line 36
    check-cast v1, Ljava/lang/Integer;

    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    const/4 v1, 0x1

    .line 42
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 43
    .line 44
    .line 45
    move-result v14

    .line 46
    iget-boolean v8, v0, Ldk/a;->e:Z

    .line 47
    .line 48
    iget-boolean v9, v0, Ldk/a;->f:Z

    .line 49
    .line 50
    invoke-static/range {v7 .. v14}, Lz61/h;->a(Lx2/s;ZZLay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 51
    .line 52
    .line 53
    return-object v2

    .line 54
    :pswitch_0
    move-object v15, v6

    .line 55
    check-cast v15, Lh2/hb;

    .line 56
    .line 57
    move-object/from16 v18, v5

    .line 58
    .line 59
    check-cast v18, Li1/l;

    .line 60
    .line 61
    move-object/from16 v19, v4

    .line 62
    .line 63
    check-cast v19, Lh2/eb;

    .line 64
    .line 65
    move-object/from16 v20, v3

    .line 66
    .line 67
    check-cast v20, Le3/n0;

    .line 68
    .line 69
    sget-object v1, Lh2/hb;->a:Lh2/hb;

    .line 70
    .line 71
    sget-object v1, Lh2/hb;->a:Lh2/hb;

    .line 72
    .line 73
    move-object/from16 v21, p1

    .line 74
    .line 75
    check-cast v21, Ll2/o;

    .line 76
    .line 77
    move-object/from16 v1, p2

    .line 78
    .line 79
    check-cast v1, Ljava/lang/Integer;

    .line 80
    .line 81
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    const v1, 0x6d80c01

    .line 85
    .line 86
    .line 87
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 88
    .line 89
    .line 90
    move-result v22

    .line 91
    iget-boolean v1, v0, Ldk/a;->e:Z

    .line 92
    .line 93
    iget-boolean v0, v0, Ldk/a;->f:Z

    .line 94
    .line 95
    move/from16 v17, v0

    .line 96
    .line 97
    move/from16 v16, v1

    .line 98
    .line 99
    invoke-virtual/range {v15 .. v22}, Lh2/hb;->a(ZZLi1/l;Lh2/eb;Le3/n0;Ll2/o;I)V

    .line 100
    .line 101
    .line 102
    return-object v2

    .line 103
    :pswitch_1
    check-cast v6, Ljava/lang/String;

    .line 104
    .line 105
    check-cast v5, Ljava/lang/String;

    .line 106
    .line 107
    check-cast v4, Ljava/lang/String;

    .line 108
    .line 109
    move-object v7, v3

    .line 110
    check-cast v7, Ljava/lang/String;

    .line 111
    .line 112
    move-object/from16 v8, p1

    .line 113
    .line 114
    check-cast v8, Ll2/o;

    .line 115
    .line 116
    move-object/from16 v1, p2

    .line 117
    .line 118
    check-cast v1, Ljava/lang/Integer;

    .line 119
    .line 120
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 121
    .line 122
    .line 123
    const v1, 0x36001

    .line 124
    .line 125
    .line 126
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 127
    .line 128
    .line 129
    move-result v3

    .line 130
    iget-boolean v9, v0, Ldk/a;->e:Z

    .line 131
    .line 132
    iget-boolean v10, v0, Ldk/a;->f:Z

    .line 133
    .line 134
    move-object/from16 v23, v6

    .line 135
    .line 136
    move-object v6, v4

    .line 137
    move-object/from16 v4, v23

    .line 138
    .line 139
    invoke-static/range {v3 .. v10}, Ldk/b;->a(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;ZZ)V

    .line 140
    .line 141
    .line 142
    return-object v2

    .line 143
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
