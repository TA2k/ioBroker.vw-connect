.class public final synthetic Li91/e2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Li91/v1;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Z

.field public final synthetic i:Li1/l;


# direct methods
.method public synthetic constructor <init>(Li91/v1;Ljava/lang/String;Lay0/a;ZLi1/l;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Li91/e2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/e2;->f:Li91/v1;

    iput-object p2, p0, Li91/e2;->e:Ljava/lang/String;

    iput-object p3, p0, Li91/e2;->g:Lay0/a;

    iput-boolean p4, p0, Li91/e2;->h:Z

    iput-object p5, p0, Li91/e2;->i:Li1/l;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Li91/v1;Lay0/a;ZLi1/l;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Li91/e2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/e2;->e:Ljava/lang/String;

    iput-object p2, p0, Li91/e2;->f:Li91/v1;

    iput-object p3, p0, Li91/e2;->g:Lay0/a;

    iput-boolean p4, p0, Li91/e2;->h:Z

    iput-object p5, p0, Li91/e2;->i:Li1/l;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Li91/e2;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x1

    .line 18
    if-eq v0, v1, :cond_0

    .line 19
    .line 20
    move v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    and-int/2addr p2, v2

    .line 24
    move-object v6, p1

    .line 25
    check-cast v6, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {v6, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 34
    .line 35
    iget-object p2, p0, Li91/e2;->e:Ljava/lang/String;

    .line 36
    .line 37
    invoke-static {p1, p2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    iget-object p1, p0, Li91/e2;->f:Li91/v1;

    .line 42
    .line 43
    check-cast p1, Li91/o1;

    .line 44
    .line 45
    iget-object v1, p1, Li91/o1;->a:Li91/i1;

    .line 46
    .line 47
    const/16 v7, 0x6000

    .line 48
    .line 49
    const/4 v8, 0x0

    .line 50
    iget-object v2, p0, Li91/e2;->g:Lay0/a;

    .line 51
    .line 52
    iget-boolean v3, p0, Li91/e2;->h:Z

    .line 53
    .line 54
    iget-object v5, p0, Li91/e2;->i:Li1/l;

    .line 55
    .line 56
    invoke-static/range {v1 .. v8}, Li91/j0;->k0(Li91/i1;Lay0/a;ZLx2/s;Li1/l;Ll2/o;II)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 61
    .line 62
    .line 63
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_0
    and-int/lit8 v0, p2, 0x3

    .line 67
    .line 68
    const/4 v1, 0x2

    .line 69
    const/4 v2, 0x1

    .line 70
    if-eq v0, v1, :cond_2

    .line 71
    .line 72
    move v0, v2

    .line 73
    goto :goto_2

    .line 74
    :cond_2
    const/4 v0, 0x0

    .line 75
    :goto_2
    and-int/2addr p2, v2

    .line 76
    move-object v6, p1

    .line 77
    check-cast v6, Ll2/t;

    .line 78
    .line 79
    invoke-virtual {v6, p2, v0}, Ll2/t;->O(IZ)Z

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    if-eqz p1, :cond_3

    .line 84
    .line 85
    iget-object p1, p0, Li91/e2;->f:Li91/v1;

    .line 86
    .line 87
    check-cast p1, Li91/w1;

    .line 88
    .line 89
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 90
    .line 91
    .line 92
    const/4 p2, 0x0

    .line 93
    const-string v0, "list_item_radio_button"

    .line 94
    .line 95
    iget-object v1, p0, Li91/e2;->e:Ljava/lang/String;

    .line 96
    .line 97
    invoke-static {p2, v1, v0}, Li91/z3;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p2

    .line 101
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 102
    .line 103
    invoke-static {v0, p2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 104
    .line 105
    .line 106
    move-result-object v4

    .line 107
    iget-boolean v1, p1, Li91/w1;->a:Z

    .line 108
    .line 109
    const/16 v7, 0x6000

    .line 110
    .line 111
    const/4 v8, 0x0

    .line 112
    iget-object v2, p0, Li91/e2;->g:Lay0/a;

    .line 113
    .line 114
    iget-boolean v3, p0, Li91/e2;->h:Z

    .line 115
    .line 116
    iget-object v5, p0, Li91/e2;->i:Li1/l;

    .line 117
    .line 118
    invoke-static/range {v1 .. v8}, Li91/j0;->l0(ZLay0/a;ZLx2/s;Li1/l;Ll2/o;II)V

    .line 119
    .line 120
    .line 121
    goto :goto_3

    .line 122
    :cond_3
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 123
    .line 124
    .line 125
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 126
    .line 127
    return-object p0

    .line 128
    nop

    .line 129
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
