.class public final Lh2/u3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J


# direct methods
.method public synthetic constructor <init>(JI)V
    .locals 0

    .line 1
    iput p3, p0, Lh2/u3;->d:I

    .line 2
    .line 3
    iput-wide p1, p0, Lh2/u3;->e:J

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh2/u3;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lk21/a;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Lg21/a;

    .line 15
    .line 16
    const-string v3, "$this$single"

    .line 17
    .line 18
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v3, "it"

    .line 22
    .line 23
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    new-instance v2, Ljy/h;

    .line 27
    .line 28
    iget-wide v3, v0, Lh2/u3;->e:J

    .line 29
    .line 30
    invoke-direct {v2, v1, v3, v4}, Ljy/h;-><init>(Lk21/a;J)V

    .line 31
    .line 32
    .line 33
    return-object v2

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
    check-cast v2, Ljava/lang/Number;

    .line 41
    .line 42
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    and-int/lit8 v3, v2, 0x3

    .line 47
    .line 48
    const/4 v4, 0x2

    .line 49
    const/4 v5, 0x1

    .line 50
    if-eq v3, v4, :cond_0

    .line 51
    .line 52
    move v3, v5

    .line 53
    goto :goto_0

    .line 54
    :cond_0
    const/4 v3, 0x0

    .line 55
    :goto_0
    and-int/2addr v2, v5

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
    const/16 v25, 0x0

    .line 65
    .line 66
    const v26, 0x3fffa

    .line 67
    .line 68
    .line 69
    const-string v4, "-"

    .line 70
    .line 71
    const/4 v5, 0x0

    .line 72
    iget-wide v6, v0, Lh2/u3;->e:J

    .line 73
    .line 74
    const-wide/16 v8, 0x0

    .line 75
    .line 76
    const/4 v10, 0x0

    .line 77
    const-wide/16 v11, 0x0

    .line 78
    .line 79
    const/4 v13, 0x0

    .line 80
    const/4 v14, 0x0

    .line 81
    const-wide/16 v15, 0x0

    .line 82
    .line 83
    const/16 v17, 0x0

    .line 84
    .line 85
    const/16 v18, 0x0

    .line 86
    .line 87
    const/16 v19, 0x0

    .line 88
    .line 89
    const/16 v20, 0x0

    .line 90
    .line 91
    const/16 v21, 0x0

    .line 92
    .line 93
    const/16 v22, 0x0

    .line 94
    .line 95
    const/16 v24, 0x6

    .line 96
    .line 97
    move-object/from16 v23, v1

    .line 98
    .line 99
    invoke-static/range {v4 .. v26}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 100
    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_1
    move-object/from16 v23, v1

    .line 104
    .line 105
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 106
    .line 107
    .line 108
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 109
    .line 110
    return-object v0

    .line 111
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
