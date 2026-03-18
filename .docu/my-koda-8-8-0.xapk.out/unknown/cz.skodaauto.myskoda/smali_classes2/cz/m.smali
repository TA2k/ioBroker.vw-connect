.class public final synthetic Lcz/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/util/Collection;I)V
    .locals 0

    .line 1
    iput p3, p0, Lcz/m;->d:I

    iput p1, p0, Lcz/m;->e:I

    iput-object p2, p0, Lcz/m;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;II)V
    .locals 0

    .line 2
    iput p3, p0, Lcz/m;->d:I

    iput-object p1, p0, Lcz/m;->f:Ljava/lang/Object;

    iput p2, p0, Lcz/m;->e:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lcz/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcz/m;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lv2/o;

    .line 9
    .line 10
    check-cast p1, Lt3/y;

    .line 11
    .line 12
    const-string v1, "it"

    .line 13
    .line 14
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    sget-object v1, Lxf0/z2;->a:Ljava/util/List;

    .line 18
    .line 19
    iget p0, p0, Lcz/m;->e:I

    .line 20
    .line 21
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    invoke-interface {v1, v2}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    invoke-static {p1}, Lt3/k1;->f(Lt3/y;)Ld3/c;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-virtual {p1}, Ld3/c;->b()J

    .line 36
    .line 37
    .line 38
    move-result-wide v1

    .line 39
    new-instance p1, Ld3/b;

    .line 40
    .line 41
    invoke-direct {p1, v1, v2}, Ld3/b;-><init>(J)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0, p0, p1}, Lv2/o;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_0
    iget-object v0, p0, Lcz/m;->f:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v0, Ljava/util/Collection;

    .line 53
    .line 54
    check-cast p1, Ljava/util/List;

    .line 55
    .line 56
    iget p0, p0, Lcz/m;->e:I

    .line 57
    .line 58
    invoke-interface {p1, p0, v0}, Ljava/util/List;->addAll(ILjava/util/Collection;)Z

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0

    .line 67
    :pswitch_1
    iget-object v0, p0, Lcz/m;->f:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v0, Ln1/v;

    .line 70
    .line 71
    check-cast p1, Lo1/j0;

    .line 72
    .line 73
    iget-object v0, v0, Ln1/v;->a:Lm1/a;

    .line 74
    .line 75
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    if-eqz v1, :cond_1

    .line 80
    .line 81
    invoke-virtual {v1}, Lv2/f;->e()Lay0/k;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    goto :goto_0

    .line 86
    :cond_1
    const/4 v2, 0x0

    .line 87
    :goto_0
    invoke-static {v1}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 88
    .line 89
    .line 90
    move-result-object v3

    .line 91
    invoke-static {v1, v3, v2}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 95
    .line 96
    .line 97
    iget v0, p1, Lo1/j0;->a:I

    .line 98
    .line 99
    const/4 v1, -0x1

    .line 100
    if-ne v0, v1, :cond_2

    .line 101
    .line 102
    const/4 v0, 0x2

    .line 103
    :cond_2
    const/4 v1, 0x0

    .line 104
    :goto_1
    if-ge v1, v0, :cond_3

    .line 105
    .line 106
    iget v2, p0, Lcz/m;->e:I

    .line 107
    .line 108
    add-int/2addr v2, v1

    .line 109
    invoke-virtual {p1, v2}, Lo1/j0;->a(I)V

    .line 110
    .line 111
    .line 112
    add-int/lit8 v1, v1, 0x1

    .line 113
    .line 114
    goto :goto_1

    .line 115
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 116
    .line 117
    return-object p0

    .line 118
    :pswitch_2
    iget-object v0, p0, Lcz/m;->f:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast v0, Lay0/k;

    .line 121
    .line 122
    check-cast p1, Ljava/lang/Boolean;

    .line 123
    .line 124
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 125
    .line 126
    .line 127
    iget p0, p0, Lcz/m;->e:I

    .line 128
    .line 129
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 137
    .line 138
    return-object p0

    .line 139
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
