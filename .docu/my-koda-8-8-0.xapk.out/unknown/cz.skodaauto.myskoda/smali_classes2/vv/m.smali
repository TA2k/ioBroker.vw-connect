.class public final Lvv/m;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lay0/n;


# direct methods
.method public synthetic constructor <init>(ILay0/n;)V
    .locals 0

    .line 1
    iput p1, p0, Lvv/m;->f:I

    .line 2
    .line 3
    iput-object p2, p0, Lvv/m;->g:Lay0/n;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lvv/m;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Number;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    and-int/lit8 p2, p2, 0xb

    .line 15
    .line 16
    const/4 v0, 0x2

    .line 17
    if-ne p2, v0, :cond_1

    .line 18
    .line 19
    move-object p2, p1

    .line 20
    check-cast p2, Ll2/t;

    .line 21
    .line 22
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-nez v0, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 30
    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_1
    :goto_0
    const/4 p2, 0x0

    .line 34
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 35
    .line 36
    .line 37
    move-result-object p2

    .line 38
    iget-object p0, p0, Lvv/m;->g:Lay0/n;

    .line 39
    .line 40
    invoke-interface {p0, p1, p2}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    return-object p0

    .line 46
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 47
    .line 48
    check-cast p2, Ljava/lang/Number;

    .line 49
    .line 50
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 51
    .line 52
    .line 53
    move-result p2

    .line 54
    and-int/lit8 p2, p2, 0xb

    .line 55
    .line 56
    const/4 v0, 0x2

    .line 57
    if-ne p2, v0, :cond_3

    .line 58
    .line 59
    move-object p2, p1

    .line 60
    check-cast p2, Ll2/t;

    .line 61
    .line 62
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    if-nez v0, :cond_2

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_2
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 70
    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_3
    :goto_2
    const/4 p2, 0x0

    .line 74
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 75
    .line 76
    .line 77
    move-result-object p2

    .line 78
    iget-object p0, p0, Lvv/m;->g:Lay0/n;

    .line 79
    .line 80
    invoke-interface {p0, p1, p2}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 84
    .line 85
    return-object p0

    .line 86
    :pswitch_1
    check-cast p1, Ll2/o;

    .line 87
    .line 88
    check-cast p2, Ljava/lang/Number;

    .line 89
    .line 90
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 91
    .line 92
    .line 93
    move-result p2

    .line 94
    and-int/lit8 p2, p2, 0xb

    .line 95
    .line 96
    const/4 v0, 0x2

    .line 97
    if-ne p2, v0, :cond_5

    .line 98
    .line 99
    move-object p2, p1

    .line 100
    check-cast p2, Ll2/t;

    .line 101
    .line 102
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 103
    .line 104
    .line 105
    move-result v0

    .line 106
    if-nez v0, :cond_4

    .line 107
    .line 108
    goto :goto_4

    .line 109
    :cond_4
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 110
    .line 111
    .line 112
    goto :goto_5

    .line 113
    :cond_5
    :goto_4
    const/4 p2, 0x0

    .line 114
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 115
    .line 116
    .line 117
    move-result-object p2

    .line 118
    iget-object p0, p0, Lvv/m;->g:Lay0/n;

    .line 119
    .line 120
    invoke-interface {p0, p1, p2}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 124
    .line 125
    return-object p0

    .line 126
    nop

    .line 127
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
