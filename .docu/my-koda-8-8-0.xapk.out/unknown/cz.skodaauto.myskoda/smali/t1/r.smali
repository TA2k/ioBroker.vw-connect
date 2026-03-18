.class public final synthetic Lt1/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt1/p0;


# direct methods
.method public synthetic constructor <init>(Lt1/p0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lt1/r;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lt1/r;->e:Lt1/p0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lt1/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll4/i;

    .line 7
    .line 8
    iget-object p0, p0, Lt1/r;->e:Lt1/p0;

    .line 9
    .line 10
    iget-object p0, p0, Lt1/p0;->r:Lt1/m0;

    .line 11
    .line 12
    iget p1, p1, Ll4/i;->a:I

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Lt1/m0;->b(I)Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Ll4/i;

    .line 24
    .line 25
    iget-object p0, p0, Lt1/r;->e:Lt1/p0;

    .line 26
    .line 27
    iget-object p0, p0, Lt1/p0;->r:Lt1/m0;

    .line 28
    .line 29
    iget p1, p1, Ll4/i;->a:I

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lt1/m0;->b(I)Z

    .line 32
    .line 33
    .line 34
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_1
    iget-object p0, p0, Lt1/r;->e:Lt1/p0;

    .line 38
    .line 39
    iget-object v0, p0, Lt1/p0;->t:Ll2/j1;

    .line 40
    .line 41
    check-cast p1, Ll4/v;

    .line 42
    .line 43
    iget-object v1, p1, Ll4/v;->a:Lg4/g;

    .line 44
    .line 45
    iget-object v1, v1, Lg4/g;->e:Ljava/lang/String;

    .line 46
    .line 47
    iget-object v2, p0, Lt1/p0;->j:Lg4/g;

    .line 48
    .line 49
    if-eqz v2, :cond_0

    .line 50
    .line 51
    iget-object v2, v2, Lg4/g;->e:Ljava/lang/String;

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    const/4 v2, 0x0

    .line 55
    :goto_0
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    if-nez v1, :cond_2

    .line 60
    .line 61
    sget-object v1, Lt1/c0;->d:Lt1/c0;

    .line 62
    .line 63
    iget-object v2, p0, Lt1/p0;->k:Ll2/j1;

    .line 64
    .line 65
    invoke-virtual {v2, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    check-cast v1, Ljava/lang/Boolean;

    .line 73
    .line 74
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    if-eqz v1, :cond_1

    .line 79
    .line 80
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 81
    .line 82
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_1
    iget-object v0, p0, Lt1/p0;->s:Ll2/j1;

    .line 87
    .line 88
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    :cond_2
    :goto_1
    sget-wide v0, Lg4/o0;->b:J

    .line 94
    .line 95
    invoke-virtual {p0, v0, v1}, Lt1/p0;->f(J)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {p0, v0, v1}, Lt1/p0;->e(J)V

    .line 99
    .line 100
    .line 101
    iget-object v0, p0, Lt1/p0;->u:Lay0/k;

    .line 102
    .line 103
    invoke-interface {v0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    iget-object p0, p0, Lt1/p0;->b:Ll2/u1;

    .line 107
    .line 108
    invoke-virtual {p0}, Ll2/u1;->c()V

    .line 109
    .line 110
    .line 111
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 112
    .line 113
    return-object p0

    .line 114
    :pswitch_2
    check-cast p1, Ljava/lang/Boolean;

    .line 115
    .line 116
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 117
    .line 118
    .line 119
    iget-object p0, p0, Lt1/r;->e:Lt1/p0;

    .line 120
    .line 121
    iget-object p0, p0, Lt1/p0;->q:Ll2/j1;

    .line 122
    .line 123
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 127
    .line 128
    return-object p0

    .line 129
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
