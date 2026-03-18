.class public final synthetic Luz/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Ltz/f0;

.field public final synthetic g:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Ltz/f0;Lay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Luz/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Luz/i;->e:Lay0/a;

    iput-object p2, p0, Luz/i;->f:Ltz/f0;

    iput-object p3, p0, Luz/i;->g:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Ltz/f0;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 2
    const/4 p4, 0x0

    iput p4, p0, Luz/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Luz/i;->f:Ltz/f0;

    iput-object p2, p0, Luz/i;->e:Lay0/a;

    iput-object p3, p0, Luz/i;->g:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Luz/i;->d:I

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
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    and-int/lit8 v3, v2, 0x3

    .line 21
    .line 22
    const/4 v4, 0x2

    .line 23
    const/4 v5, 0x1

    .line 24
    if-eq v3, v4, :cond_0

    .line 25
    .line 26
    move v3, v5

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v3, 0x0

    .line 29
    :goto_0
    and-int/2addr v2, v5

    .line 30
    move-object v11, v1

    .line 31
    check-cast v11, Ll2/t;

    .line 32
    .line 33
    invoke-virtual {v11, v2, v3}, Ll2/t;->O(IZ)Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-eqz v1, :cond_1

    .line 38
    .line 39
    const v1, 0x7f120464

    .line 40
    .line 41
    .line 42
    invoke-static {v11, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v5

    .line 46
    new-instance v7, Li91/w2;

    .line 47
    .line 48
    iget-object v1, v0, Luz/i;->e:Lay0/a;

    .line 49
    .line 50
    const/4 v2, 0x3

    .line 51
    invoke-direct {v7, v1, v2}, Li91/w2;-><init>(Lay0/a;I)V

    .line 52
    .line 53
    .line 54
    iget-object v1, v0, Luz/i;->f:Ltz/f0;

    .line 55
    .line 56
    iget-boolean v1, v1, Ltz/f0;->f:Z

    .line 57
    .line 58
    new-instance v12, Li91/v2;

    .line 59
    .line 60
    const/16 v16, 0x0

    .line 61
    .line 62
    const/4 v14, 0x4

    .line 63
    const v13, 0x7f080429

    .line 64
    .line 65
    .line 66
    iget-object v15, v0, Luz/i;->g:Lay0/a;

    .line 67
    .line 68
    move/from16 v17, v1

    .line 69
    .line 70
    invoke-direct/range {v12 .. v17}, Li91/v2;-><init>(IILay0/a;Ljava/lang/String;Z)V

    .line 71
    .line 72
    .line 73
    invoke-static {v12}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 74
    .line 75
    .line 76
    move-result-object v8

    .line 77
    const/4 v12, 0x0

    .line 78
    const/16 v13, 0x33d

    .line 79
    .line 80
    const/4 v4, 0x0

    .line 81
    const/4 v6, 0x0

    .line 82
    const/4 v9, 0x0

    .line 83
    const/4 v10, 0x0

    .line 84
    invoke-static/range {v4 .. v13}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 85
    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_1
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 89
    .line 90
    .line 91
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    return-object v0

    .line 94
    :pswitch_0
    move-object/from16 v1, p1

    .line 95
    .line 96
    check-cast v1, Ll2/o;

    .line 97
    .line 98
    move-object/from16 v2, p2

    .line 99
    .line 100
    check-cast v2, Ljava/lang/Integer;

    .line 101
    .line 102
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 103
    .line 104
    .line 105
    const/4 v2, 0x1

    .line 106
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 107
    .line 108
    .line 109
    move-result v2

    .line 110
    iget-object v3, v0, Luz/i;->f:Ltz/f0;

    .line 111
    .line 112
    iget-object v4, v0, Luz/i;->e:Lay0/a;

    .line 113
    .line 114
    iget-object v0, v0, Luz/i;->g:Lay0/a;

    .line 115
    .line 116
    invoke-static {v3, v4, v0, v1, v2}, Luz/k0;->o(Ltz/f0;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 117
    .line 118
    .line 119
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 120
    .line 121
    return-object v0

    .line 122
    nop

    .line 123
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
