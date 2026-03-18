.class public final synthetic Lk1/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:I

.field public final synthetic g:Lt3/s0;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lt3/e1;Lt3/p0;Lt3/s0;IILk1/p;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lk1/o;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lk1/o;->h:Ljava/lang/Object;

    iput-object p2, p0, Lk1/o;->i:Ljava/lang/Object;

    iput-object p3, p0, Lk1/o;->g:Lt3/s0;

    iput p4, p0, Lk1/o;->e:I

    iput p5, p0, Lk1/o;->f:I

    iput-object p6, p0, Lk1/o;->j:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>([Lt3/e1;Lk1/s;IILt3/s0;[I)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lk1/o;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lk1/o;->h:Ljava/lang/Object;

    iput-object p2, p0, Lk1/o;->i:Ljava/lang/Object;

    iput p3, p0, Lk1/o;->e:I

    iput p4, p0, Lk1/o;->f:I

    iput-object p5, p0, Lk1/o;->g:Lt3/s0;

    iput-object p6, p0, Lk1/o;->j:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lk1/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lk1/o;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, [Lt3/e1;

    .line 9
    .line 10
    iget-object v1, p0, Lk1/o;->i:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lk1/s;

    .line 13
    .line 14
    iget-object v2, p0, Lk1/o;->j:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, [I

    .line 17
    .line 18
    check-cast p1, Lt3/d1;

    .line 19
    .line 20
    array-length v3, v0

    .line 21
    const/4 v4, 0x0

    .line 22
    move v5, v4

    .line 23
    move v6, v5

    .line 24
    :goto_0
    if-ge v5, v3, :cond_3

    .line 25
    .line 26
    aget-object v7, v0, v5

    .line 27
    .line 28
    add-int/lit8 v8, v6, 0x1

    .line 29
    .line 30
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v7}, Lt3/e1;->l()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v9

    .line 37
    instance-of v10, v9, Lk1/d1;

    .line 38
    .line 39
    const/4 v11, 0x0

    .line 40
    if-eqz v10, :cond_0

    .line 41
    .line 42
    check-cast v9, Lk1/d1;

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_0
    move-object v9, v11

    .line 46
    :goto_1
    iget-object v10, p0, Lk1/o;->g:Lt3/s0;

    .line 47
    .line 48
    invoke-interface {v10}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 49
    .line 50
    .line 51
    move-result-object v10

    .line 52
    if-eqz v9, :cond_1

    .line 53
    .line 54
    iget-object v11, v9, Lk1/d1;->c:Lk1/d;

    .line 55
    .line 56
    :cond_1
    iget v9, p0, Lk1/o;->e:I

    .line 57
    .line 58
    if-eqz v11, :cond_2

    .line 59
    .line 60
    iget v12, v7, Lt3/e1;->d:I

    .line 61
    .line 62
    sub-int/2addr v9, v12

    .line 63
    iget v12, p0, Lk1/o;->f:I

    .line 64
    .line 65
    invoke-virtual {v11, v9, v10, v7, v12}, Lk1/d;->e(ILt4/m;Lt3/e1;I)I

    .line 66
    .line 67
    .line 68
    move-result v9

    .line 69
    goto :goto_2

    .line 70
    :cond_2
    iget-object v11, v1, Lk1/s;->b:Lx2/d;

    .line 71
    .line 72
    iget v12, v7, Lt3/e1;->d:I

    .line 73
    .line 74
    sub-int/2addr v9, v12

    .line 75
    invoke-interface {v11, v4, v9, v10}, Lx2/d;->a(IILt4/m;)I

    .line 76
    .line 77
    .line 78
    move-result v9

    .line 79
    :goto_2
    aget v6, v2, v6

    .line 80
    .line 81
    invoke-static {p1, v7, v9, v6}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 82
    .line 83
    .line 84
    add-int/lit8 v5, v5, 0x1

    .line 85
    .line 86
    move v6, v8

    .line 87
    goto :goto_0

    .line 88
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 89
    .line 90
    return-object p0

    .line 91
    :pswitch_0
    iget-object v0, p0, Lk1/o;->h:Ljava/lang/Object;

    .line 92
    .line 93
    move-object v2, v0

    .line 94
    check-cast v2, Lt3/e1;

    .line 95
    .line 96
    iget-object v0, p0, Lk1/o;->i:Ljava/lang/Object;

    .line 97
    .line 98
    move-object v3, v0

    .line 99
    check-cast v3, Lt3/p0;

    .line 100
    .line 101
    iget-object v0, p0, Lk1/o;->j:Ljava/lang/Object;

    .line 102
    .line 103
    check-cast v0, Lk1/p;

    .line 104
    .line 105
    move-object v1, p1

    .line 106
    check-cast v1, Lt3/d1;

    .line 107
    .line 108
    iget-object p1, p0, Lk1/o;->g:Lt3/s0;

    .line 109
    .line 110
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 111
    .line 112
    .line 113
    move-result-object v4

    .line 114
    iget-object v7, v0, Lk1/p;->a:Lx2/e;

    .line 115
    .line 116
    iget v5, p0, Lk1/o;->e:I

    .line 117
    .line 118
    iget v6, p0, Lk1/o;->f:I

    .line 119
    .line 120
    invoke-static/range {v1 .. v7}, Lk1/n;->b(Lt3/d1;Lt3/e1;Lt3/p0;Lt4/m;IILx2/e;)V

    .line 121
    .line 122
    .line 123
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 124
    .line 125
    return-object p0

    .line 126
    nop

    .line 127
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
