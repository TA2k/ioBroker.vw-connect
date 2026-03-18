.class public final synthetic Lmg/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Ll2/b1;I)V
    .locals 0

    .line 1
    iput p3, p0, Lmg/d;->d:I

    iput-object p1, p0, Lmg/d;->e:Lay0/k;

    iput-object p2, p0, Lmg/d;->f:Ll2/b1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ll2/b1;Lay0/k;I)V
    .locals 0

    .line 2
    iput p3, p0, Lmg/d;->d:I

    iput-object p1, p0, Lmg/d;->f:Ll2/b1;

    iput-object p2, p0, Lmg/d;->e:Lay0/k;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lmg/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ld3/b;

    .line 7
    .line 8
    iget-object v0, p0, Lmg/d;->f:Ll2/b1;

    .line 9
    .line 10
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Lg4/l0;

    .line 15
    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    iget-wide v1, p1, Ld3/b;->a:J

    .line 19
    .line 20
    iget-object p1, v0, Lg4/l0;->b:Lg4/o;

    .line 21
    .line 22
    invoke-virtual {p1, v1, v2}, Lg4/o;->g(J)I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    iget-object p0, p0, Lmg/d;->e:Lay0/k;

    .line 31
    .line 32
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_0
    check-cast p1, Lg4/l0;

    .line 39
    .line 40
    iget-object v0, p0, Lmg/d;->f:Ll2/b1;

    .line 41
    .line 42
    invoke-interface {v0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Lmg/d;->e:Lay0/k;

    .line 46
    .line 47
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    return-object p0

    .line 53
    :pswitch_1
    check-cast p1, Lpe/b;

    .line 54
    .line 55
    const-string v0, "selectedType"

    .line 56
    .line 57
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    iget-object v0, p0, Lmg/d;->f:Ll2/b1;

    .line 61
    .line 62
    invoke-interface {v0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iget-object p0, p0, Lmg/d;->e:Lay0/k;

    .line 66
    .line 67
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    goto :goto_0

    .line 71
    :pswitch_2
    check-cast p1, Ljava/lang/String;

    .line 72
    .line 73
    const-string v0, "pairedWallboxId"

    .line 74
    .line 75
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    iget-object v0, p0, Lmg/d;->f:Ll2/b1;

    .line 79
    .line 80
    invoke-interface {v0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    new-instance p1, Lmh/p;

    .line 84
    .line 85
    sget-object v0, Lmh/f;->b:Lmh/f;

    .line 86
    .line 87
    invoke-direct {p1, v0}, Lmh/p;-><init>(Lmh/j;)V

    .line 88
    .line 89
    .line 90
    iget-object p0, p0, Lmg/d;->e:Lay0/k;

    .line 91
    .line 92
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    goto :goto_0

    .line 96
    :pswitch_3
    check-cast p1, Lz9/y;

    .line 97
    .line 98
    const-string v0, "$this$navigator"

    .line 99
    .line 100
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    new-instance v0, Leh/d;

    .line 104
    .line 105
    const/4 v1, 0x3

    .line 106
    invoke-direct {v0, p1, v1}, Leh/d;-><init>(Lz9/y;I)V

    .line 107
    .line 108
    .line 109
    const-string v1, "/void"

    .line 110
    .line 111
    invoke-virtual {p1, v1, v0}, Lz9/y;->d(Ljava/lang/String;Lay0/k;)V

    .line 112
    .line 113
    .line 114
    iget-object p1, p0, Lmg/d;->f:Ll2/b1;

    .line 115
    .line 116
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    check-cast p1, Lmg/c;

    .line 121
    .line 122
    iget-object p1, p1, Lmg/c;->g:Log/i;

    .line 123
    .line 124
    sget-object v0, Log/i;->f:Log/i;

    .line 125
    .line 126
    if-eq p1, v0, :cond_1

    .line 127
    .line 128
    const/4 p1, 0x1

    .line 129
    goto :goto_1

    .line 130
    :cond_1
    const/4 p1, 0x0

    .line 131
    :goto_1
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 132
    .line 133
    .line 134
    move-result-object p1

    .line 135
    iget-object p0, p0, Lmg/d;->e:Lay0/k;

    .line 136
    .line 137
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    goto :goto_0

    .line 141
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
