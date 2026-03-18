.class public final synthetic Lc2/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc2/e;


# direct methods
.method public synthetic constructor <init>(Lc2/e;I)V
    .locals 0

    .line 1
    iput p2, p0, Lc2/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc2/c;->e:Lc2/e;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lc2/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lc2/c;->e:Lc2/e;

    .line 7
    .line 8
    iget-object v0, p0, Lc2/e;->v:Lt1/p0;

    .line 9
    .line 10
    iget-object v1, p0, Lc2/e;->B:Lc3/q;

    .line 11
    .line 12
    iget-boolean p0, p0, Lc2/e;->w:Z

    .line 13
    .line 14
    invoke-virtual {v0}, Lt1/p0;->b()Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-nez v2, :cond_0

    .line 19
    .line 20
    invoke-static {v1}, Lc3/q;->b(Lc3/q;)V

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    if-nez p0, :cond_1

    .line 25
    .line 26
    iget-object p0, v0, Lt1/p0;->c:Lw3/b2;

    .line 27
    .line 28
    if-eqz p0, :cond_1

    .line 29
    .line 30
    check-cast p0, Lw3/i1;

    .line 31
    .line 32
    invoke-virtual {p0}, Lw3/i1;->b()V

    .line 33
    .line 34
    .line 35
    :cond_1
    :goto_0
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_0
    iget-object p0, p0, Lc2/c;->e:Lc2/e;

    .line 39
    .line 40
    iget-object v0, p0, Lc2/e;->v:Lt1/p0;

    .line 41
    .line 42
    iget-object v0, v0, Lt1/p0;->w:Lt1/r;

    .line 43
    .line 44
    iget-object p0, p0, Lc2/e;->A:Ll4/j;

    .line 45
    .line 46
    iget p0, p0, Ll4/j;->e:I

    .line 47
    .line 48
    iget-object v0, v0, Lt1/r;->e:Lt1/p0;

    .line 49
    .line 50
    iget-object v0, v0, Lt1/p0;->r:Lt1/m0;

    .line 51
    .line 52
    invoke-virtual {v0, p0}, Lt1/m0;->b(I)Z

    .line 53
    .line 54
    .line 55
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 56
    .line 57
    return-object p0

    .line 58
    :pswitch_1
    iget-object p0, p0, Lc2/c;->e:Lc2/e;

    .line 59
    .line 60
    iget-object p0, p0, Lc2/e;->z:Le2/w0;

    .line 61
    .line 62
    invoke-virtual {p0}, Le2/w0;->o()V

    .line 63
    .line 64
    .line 65
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 66
    .line 67
    return-object p0

    .line 68
    :pswitch_2
    iget-object p0, p0, Lc2/c;->e:Lc2/e;

    .line 69
    .line 70
    invoke-static {p0}, Lv3/f;->u(Lv3/m;)V

    .line 71
    .line 72
    .line 73
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 74
    .line 75
    return-object p0

    .line 76
    :pswitch_3
    iget-object p0, p0, Lc2/c;->e:Lc2/e;

    .line 77
    .line 78
    iget-object p0, p0, Lc2/e;->z:Le2/w0;

    .line 79
    .line 80
    invoke-virtual {p0}, Le2/w0;->f()V

    .line 81
    .line 82
    .line 83
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 84
    .line 85
    return-object p0

    .line 86
    :pswitch_4
    iget-object p0, p0, Lc2/c;->e:Lc2/e;

    .line 87
    .line 88
    iget-object p0, p0, Lc2/e;->z:Le2/w0;

    .line 89
    .line 90
    const/4 v0, 0x1

    .line 91
    invoke-virtual {p0, v0}, Le2/w0;->d(Z)Lvy0/x1;

    .line 92
    .line 93
    .line 94
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 95
    .line 96
    return-object p0

    .line 97
    :pswitch_5
    iget-object p0, p0, Lc2/c;->e:Lc2/e;

    .line 98
    .line 99
    iget-object p0, p0, Lc2/e;->z:Le2/w0;

    .line 100
    .line 101
    const/4 v0, 0x1

    .line 102
    invoke-virtual {p0, v0}, Le2/w0;->h(Z)V

    .line 103
    .line 104
    .line 105
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 106
    .line 107
    return-object p0

    .line 108
    :pswitch_6
    iget-object p0, p0, Lc2/c;->e:Lc2/e;

    .line 109
    .line 110
    invoke-static {p0}, Lv3/f;->u(Lv3/m;)V

    .line 111
    .line 112
    .line 113
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 114
    .line 115
    return-object p0

    .line 116
    nop

    .line 117
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
