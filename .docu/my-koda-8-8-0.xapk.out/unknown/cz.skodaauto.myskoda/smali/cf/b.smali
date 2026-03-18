.class public final synthetic Lcf/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x5

    iput v0, p0, Lcf/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcf/b;->e:Lay0/a;

    iput-object p2, p0, Lcf/b;->f:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Lay0/a;Lay0/k;II)V
    .locals 0

    .line 2
    iput p4, p0, Lcf/b;->d:I

    iput-object p1, p0, Lcf/b;->e:Lay0/a;

    iput-object p2, p0, Lcf/b;->f:Lay0/k;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lay0/k;Lay0/a;II)V
    .locals 0

    .line 3
    iput p4, p0, Lcf/b;->d:I

    iput-object p1, p0, Lcf/b;->f:Lay0/k;

    iput-object p2, p0, Lcf/b;->e:Lay0/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lcf/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Integer;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 p2, 0x1

    .line 14
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    iget-object v0, p0, Lcf/b;->e:Lay0/a;

    .line 19
    .line 20
    iget-object p0, p0, Lcf/b;->f:Lay0/k;

    .line 21
    .line 22
    invoke-static {p2, v0, p0, p1}, Lxk0/h;->j(ILay0/a;Lay0/k;Ll2/o;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    check-cast p1, Ljava/time/LocalDate;

    .line 29
    .line 30
    check-cast p2, Ljava/time/LocalDate;

    .line 31
    .line 32
    const-string v0, "from"

    .line 33
    .line 34
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string v0, "to"

    .line 38
    .line 39
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    iget-object v0, p0, Lcf/b;->e:Lay0/a;

    .line 43
    .line 44
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    new-instance v0, Lrd0/c0;

    .line 48
    .line 49
    invoke-direct {v0, p1, p2}, Lrd0/c0;-><init>(Ljava/time/LocalDate;Ljava/time/LocalDate;)V

    .line 50
    .line 51
    .line 52
    iget-object p0, p0, Lcf/b;->f:Lay0/k;

    .line 53
    .line 54
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :pswitch_1
    check-cast p1, Ll2/o;

    .line 59
    .line 60
    check-cast p2, Ljava/lang/Integer;

    .line 61
    .line 62
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 63
    .line 64
    .line 65
    const/4 p2, 0x1

    .line 66
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 67
    .line 68
    .line 69
    move-result p2

    .line 70
    iget-object v0, p0, Lcf/b;->e:Lay0/a;

    .line 71
    .line 72
    iget-object p0, p0, Lcf/b;->f:Lay0/k;

    .line 73
    .line 74
    invoke-static {p2, v0, p0, p1}, Lkp/b0;->b(ILay0/a;Lay0/k;Ll2/o;)V

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    :pswitch_2
    check-cast p1, Ll2/o;

    .line 79
    .line 80
    check-cast p2, Ljava/lang/Integer;

    .line 81
    .line 82
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 83
    .line 84
    .line 85
    const/4 p2, 0x1

    .line 86
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 87
    .line 88
    .line 89
    move-result p2

    .line 90
    iget-object v0, p0, Lcf/b;->e:Lay0/a;

    .line 91
    .line 92
    iget-object p0, p0, Lcf/b;->f:Lay0/k;

    .line 93
    .line 94
    invoke-static {p2, v0, p0, p1}, Ll20/a;->q(ILay0/a;Lay0/k;Ll2/o;)V

    .line 95
    .line 96
    .line 97
    goto :goto_0

    .line 98
    :pswitch_3
    check-cast p1, Ll2/o;

    .line 99
    .line 100
    check-cast p2, Ljava/lang/Integer;

    .line 101
    .line 102
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 103
    .line 104
    .line 105
    const/4 p2, 0x1

    .line 106
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 107
    .line 108
    .line 109
    move-result p2

    .line 110
    iget-object v0, p0, Lcf/b;->e:Lay0/a;

    .line 111
    .line 112
    iget-object p0, p0, Lcf/b;->f:Lay0/k;

    .line 113
    .line 114
    invoke-static {p2, v0, p0, p1}, Ll20/a;->g(ILay0/a;Lay0/k;Ll2/o;)V

    .line 115
    .line 116
    .line 117
    goto :goto_0

    .line 118
    :pswitch_4
    check-cast p1, Ll2/o;

    .line 119
    .line 120
    check-cast p2, Ljava/lang/Integer;

    .line 121
    .line 122
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 123
    .line 124
    .line 125
    const/4 p2, 0x1

    .line 126
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 127
    .line 128
    .line 129
    move-result p2

    .line 130
    iget-object v0, p0, Lcf/b;->e:Lay0/a;

    .line 131
    .line 132
    iget-object p0, p0, Lcf/b;->f:Lay0/k;

    .line 133
    .line 134
    invoke-static {p2, v0, p0, p1}, Lh70/a;->d(ILay0/a;Lay0/k;Ll2/o;)V

    .line 135
    .line 136
    .line 137
    goto :goto_0

    .line 138
    :pswitch_5
    check-cast p1, Ll2/o;

    .line 139
    .line 140
    check-cast p2, Ljava/lang/Integer;

    .line 141
    .line 142
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 143
    .line 144
    .line 145
    const/4 p2, 0x1

    .line 146
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 147
    .line 148
    .line 149
    move-result p2

    .line 150
    iget-object v0, p0, Lcf/b;->e:Lay0/a;

    .line 151
    .line 152
    iget-object p0, p0, Lcf/b;->f:Lay0/k;

    .line 153
    .line 154
    invoke-static {p2, v0, p0, p1}, Ljp/kd;->a(ILay0/a;Lay0/k;Ll2/o;)V

    .line 155
    .line 156
    .line 157
    goto/16 :goto_0

    .line 158
    .line 159
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
