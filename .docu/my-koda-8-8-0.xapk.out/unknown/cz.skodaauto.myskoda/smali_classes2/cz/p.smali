.class public final synthetic Lcz/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lbz/u;


# direct methods
.method public synthetic constructor <init>(Lbz/u;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lcz/p;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcz/p;->e:Lbz/u;

    return-void
.end method

.method public synthetic constructor <init>(Lbz/u;I)V
    .locals 0

    .line 2
    const/4 p2, 0x1

    iput p2, p0, Lcz/p;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcz/p;->e:Lbz/u;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lcz/p;->d:I

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
    iget-object v0, v0, Lcz/p;->e:Lbz/u;

    .line 25
    .line 26
    invoke-static {v0, v1, v2}, Lcz/t;->u(Lbz/u;Ll2/o;I)V

    .line 27
    .line 28
    .line 29
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    return-object v0

    .line 32
    :pswitch_0
    move-object/from16 v1, p1

    .line 33
    .line 34
    check-cast v1, Ll2/o;

    .line 35
    .line 36
    move-object/from16 v2, p2

    .line 37
    .line 38
    check-cast v2, Ljava/lang/Integer;

    .line 39
    .line 40
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    and-int/lit8 v3, v2, 0x3

    .line 45
    .line 46
    const/4 v4, 0x2

    .line 47
    const/4 v5, 0x1

    .line 48
    if-eq v3, v4, :cond_0

    .line 49
    .line 50
    move v3, v5

    .line 51
    goto :goto_0

    .line 52
    :cond_0
    const/4 v3, 0x0

    .line 53
    :goto_0
    and-int/2addr v2, v5

    .line 54
    move-object v14, v1

    .line 55
    check-cast v14, Ll2/t;

    .line 56
    .line 57
    invoke-virtual {v14, v2, v3}, Ll2/t;->O(IZ)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 62
    .line 63
    if-eqz v1, :cond_1

    .line 64
    .line 65
    iget-object v0, v0, Lcz/p;->e:Lbz/u;

    .line 66
    .line 67
    iget-object v0, v0, Lbz/u;->d:Ljava/util/List;

    .line 68
    .line 69
    check-cast v0, Ljava/lang/Iterable;

    .line 70
    .line 71
    new-instance v1, Ljava/util/ArrayList;

    .line 72
    .line 73
    const/16 v3, 0xa

    .line 74
    .line 75
    invoke-static {v0, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 80
    .line 81
    .line 82
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 87
    .line 88
    .line 89
    move-result v3

    .line 90
    if-eqz v3, :cond_2

    .line 91
    .line 92
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    check-cast v3, Laz/j;

    .line 97
    .line 98
    iget-object v4, v3, Laz/j;->a:Ljava/lang/String;

    .line 99
    .line 100
    iget-object v11, v3, Laz/j;->b:Ljava/lang/Integer;

    .line 101
    .line 102
    iget-object v3, v3, Laz/j;->c:Ljava/lang/String;

    .line 103
    .line 104
    new-instance v5, Ljava/lang/StringBuilder;

    .line 105
    .line 106
    const-string v6, "ai_trip_picker_"

    .line 107
    .line 108
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v3

    .line 118
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 119
    .line 120
    invoke-static {v5, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 121
    .line 122
    .line 123
    move-result-object v5

    .line 124
    const/16 v16, 0x0

    .line 125
    .line 126
    const/16 v17, 0x3f7c

    .line 127
    .line 128
    const/4 v6, 0x0

    .line 129
    const/4 v7, 0x0

    .line 130
    const/4 v8, 0x0

    .line 131
    const/4 v9, 0x0

    .line 132
    const/4 v10, 0x0

    .line 133
    const/4 v12, 0x0

    .line 134
    const/4 v13, 0x0

    .line 135
    const/4 v15, 0x0

    .line 136
    invoke-static/range {v4 .. v17}, Li91/h0;->a(Ljava/lang/String;Lx2/s;Lay0/a;ZZZLjava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;III)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    goto :goto_1

    .line 143
    :cond_1
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 144
    .line 145
    .line 146
    :cond_2
    return-object v2

    .line 147
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
