.class public final synthetic Ln70/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lm70/c1;

.field public final synthetic g:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lm70/c1;Lay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Ln70/e0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ln70/e0;->e:Lay0/a;

    iput-object p2, p0, Ln70/e0;->f:Lm70/c1;

    iput-object p3, p0, Ln70/e0;->g:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lm70/c1;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 2
    const/4 p4, 0x0

    iput p4, p0, Ln70/e0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ln70/e0;->f:Lm70/c1;

    iput-object p2, p0, Ln70/e0;->e:Lay0/a;

    iput-object p3, p0, Ln70/e0;->g:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ln70/e0;->d:I

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
    const/4 v5, 0x0

    .line 24
    const/4 v6, 0x1

    .line 25
    if-eq v3, v4, :cond_0

    .line 26
    .line 27
    move v3, v6

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v3, v5

    .line 30
    :goto_0
    and-int/2addr v2, v6

    .line 31
    move-object v14, v1

    .line 32
    check-cast v14, Ll2/t;

    .line 33
    .line 34
    invoke-virtual {v14, v2, v3}, Ll2/t;->O(IZ)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_2

    .line 39
    .line 40
    const v1, 0x7f121465

    .line 41
    .line 42
    .line 43
    invoke-static {v14, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v8

    .line 47
    new-instance v10, Li91/w2;

    .line 48
    .line 49
    iget-object v1, v0, Ln70/e0;->e:Lay0/a;

    .line 50
    .line 51
    const/4 v2, 0x3

    .line 52
    invoke-direct {v10, v1, v2}, Li91/w2;-><init>(Lay0/a;I)V

    .line 53
    .line 54
    .line 55
    iget-object v1, v0, Ln70/e0;->f:Lm70/c1;

    .line 56
    .line 57
    iget-object v1, v1, Lm70/c1;->a:Llf0/i;

    .line 58
    .line 59
    sget-object v2, Llf0/i;->j:Llf0/i;

    .line 60
    .line 61
    if-ne v1, v2, :cond_1

    .line 62
    .line 63
    move v5, v6

    .line 64
    :cond_1
    new-instance v1, Li91/v2;

    .line 65
    .line 66
    const-string v2, "trip_history_export"

    .line 67
    .line 68
    const v3, 0x7f0803a5

    .line 69
    .line 70
    .line 71
    iget-object v0, v0, Ln70/e0;->g:Lay0/a;

    .line 72
    .line 73
    invoke-direct {v1, v3, v0, v2, v5}, Li91/v2;-><init>(ILay0/a;Ljava/lang/String;Z)V

    .line 74
    .line 75
    .line 76
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 77
    .line 78
    .line 79
    move-result-object v11

    .line 80
    const/4 v15, 0x0

    .line 81
    const/16 v16, 0x33d

    .line 82
    .line 83
    const/4 v7, 0x0

    .line 84
    const/4 v9, 0x0

    .line 85
    const/4 v12, 0x0

    .line 86
    const/4 v13, 0x0

    .line 87
    invoke-static/range {v7 .. v16}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 88
    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_2
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 92
    .line 93
    .line 94
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 95
    .line 96
    return-object v0

    .line 97
    :pswitch_0
    move-object/from16 v1, p1

    .line 98
    .line 99
    check-cast v1, Ll2/o;

    .line 100
    .line 101
    move-object/from16 v2, p2

    .line 102
    .line 103
    check-cast v2, Ljava/lang/Integer;

    .line 104
    .line 105
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 106
    .line 107
    .line 108
    const/16 v2, 0x31

    .line 109
    .line 110
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 111
    .line 112
    .line 113
    move-result v2

    .line 114
    iget-object v3, v0, Ln70/e0;->f:Lm70/c1;

    .line 115
    .line 116
    iget-object v4, v0, Ln70/e0;->e:Lay0/a;

    .line 117
    .line 118
    iget-object v0, v0, Ln70/e0;->g:Lay0/a;

    .line 119
    .line 120
    invoke-static {v3, v4, v0, v1, v2}, Ln70/a;->m(Lm70/c1;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 121
    .line 122
    .line 123
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 124
    .line 125
    return-object v0

    .line 126
    nop

    .line 127
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
