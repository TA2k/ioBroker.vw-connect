.class public final synthetic Lxj/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lyj/b;

.field public final synthetic f:Lyj/b;


# direct methods
.method public synthetic constructor <init>(Lyj/b;Lyj/b;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lxj/l;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lxj/l;->e:Lyj/b;

    iput-object p2, p0, Lxj/l;->f:Lyj/b;

    return-void
.end method

.method public synthetic constructor <init>(Lyj/b;Lyj/b;I)V
    .locals 0

    .line 2
    const/4 p3, 0x1

    iput p3, p0, Lxj/l;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lxj/l;->e:Lyj/b;

    iput-object p2, p0, Lxj/l;->f:Lyj/b;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lxj/l;->d:I

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
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    iget-object v3, v0, Lxj/l;->e:Lyj/b;

    .line 25
    .line 26
    iget-object v0, v0, Lxj/l;->f:Lyj/b;

    .line 27
    .line 28
    invoke-static {v3, v0, v1, v2}, Lrp/d;->a(Lyj/b;Lyj/b;Ll2/o;I)V

    .line 29
    .line 30
    .line 31
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object v0

    .line 34
    :pswitch_0
    move-object/from16 v1, p1

    .line 35
    .line 36
    check-cast v1, Ll2/o;

    .line 37
    .line 38
    move-object/from16 v2, p2

    .line 39
    .line 40
    check-cast v2, Ljava/lang/Integer;

    .line 41
    .line 42
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    and-int/lit8 v3, v2, 0x3

    .line 47
    .line 48
    const/4 v4, 0x1

    .line 49
    const/4 v5, 0x2

    .line 50
    if-eq v3, v5, :cond_0

    .line 51
    .line 52
    move v3, v4

    .line 53
    goto :goto_0

    .line 54
    :cond_0
    const/4 v3, 0x0

    .line 55
    :goto_0
    and-int/2addr v2, v4

    .line 56
    check-cast v1, Ll2/t;

    .line 57
    .line 58
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    if-eqz v2, :cond_1

    .line 63
    .line 64
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 65
    .line 66
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    check-cast v2, Lj91/c;

    .line 71
    .line 72
    iget v2, v2, Lj91/c;->k:F

    .line 73
    .line 74
    const/4 v3, 0x0

    .line 75
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 76
    .line 77
    invoke-static {v4, v2, v3, v5}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 78
    .line 79
    .line 80
    move-result-object v10

    .line 81
    const v2, 0x7f1208a9

    .line 82
    .line 83
    .line 84
    invoke-static {v1, v2}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v6

    .line 88
    const v2, 0x7f1208a8

    .line 89
    .line 90
    .line 91
    invoke-static {v1, v2}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v7

    .line 95
    new-instance v14, Lx4/p;

    .line 96
    .line 97
    const/4 v2, 0x3

    .line 98
    invoke-direct {v14, v2}, Lx4/p;-><init>(I)V

    .line 99
    .line 100
    .line 101
    const v2, 0x7f1208a6

    .line 102
    .line 103
    .line 104
    invoke-static {v1, v2}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v9

    .line 108
    const v2, 0x7f1208a7

    .line 109
    .line 110
    .line 111
    invoke-static {v1, v2}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v12

    .line 115
    const/16 v22, 0x0

    .line 116
    .line 117
    const/16 v23, 0x3e80

    .line 118
    .line 119
    iget-object v8, v0, Lxj/l;->e:Lyj/b;

    .line 120
    .line 121
    iget-object v11, v0, Lxj/l;->f:Lyj/b;

    .line 122
    .line 123
    const/4 v13, 0x0

    .line 124
    const/4 v15, 0x0

    .line 125
    const/16 v16, 0x0

    .line 126
    .line 127
    const/16 v17, 0x0

    .line 128
    .line 129
    const/16 v18, 0x0

    .line 130
    .line 131
    const/16 v19, 0x0

    .line 132
    .line 133
    const/high16 v21, 0x6000000

    .line 134
    .line 135
    move-object/from16 v20, v1

    .line 136
    .line 137
    invoke-static/range {v6 .. v23}, Li91/j0;->d(Ljava/lang/String;Ljava/lang/String;Lay0/a;Ljava/lang/String;Lx2/s;Lay0/a;Ljava/lang/String;Lay0/a;Lx4/p;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;III)V

    .line 138
    .line 139
    .line 140
    goto :goto_1

    .line 141
    :cond_1
    move-object/from16 v20, v1

    .line 142
    .line 143
    invoke-virtual/range {v20 .. v20}, Ll2/t;->R()V

    .line 144
    .line 145
    .line 146
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 147
    .line 148
    return-object v0

    .line 149
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
