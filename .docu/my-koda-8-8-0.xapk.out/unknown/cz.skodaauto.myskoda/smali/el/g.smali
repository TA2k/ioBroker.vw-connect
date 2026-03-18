.class public final synthetic Lel/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/b1;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Ll2/b1;I)V
    .locals 0

    .line 1
    iput p3, p0, Lel/g;->d:I

    iput-object p1, p0, Lel/g;->f:Lay0/k;

    iput-object p2, p0, Lel/g;->e:Ll2/b1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ll2/b1;Lay0/k;I)V
    .locals 0

    .line 2
    iput p3, p0, Lel/g;->d:I

    iput-object p1, p0, Lel/g;->e:Ll2/b1;

    iput-object p2, p0, Lel/g;->f:Lay0/k;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lel/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lel/g;->e:Ll2/b1;

    .line 7
    .line 8
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 9
    .line 10
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    sget-object v0, Lxc/d;->a:Lxc/d;

    .line 14
    .line 15
    iget-object p0, p0, Lel/g;->f:Lay0/k;

    .line 16
    .line 17
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    return-object p0

    .line 23
    :pswitch_0
    iget-object v0, p0, Lel/g;->e:Ll2/b1;

    .line 24
    .line 25
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    check-cast v0, Lrd0/d0;

    .line 30
    .line 31
    iget v0, v0, Lrd0/d0;->a:I

    .line 32
    .line 33
    new-instance v1, Lrd0/d0;

    .line 34
    .line 35
    invoke-direct {v1, v0}, Lrd0/d0;-><init>(I)V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lel/g;->f:Lay0/k;

    .line 39
    .line 40
    invoke-interface {p0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :pswitch_1
    iget-object v0, p0, Lel/g;->e:Ll2/b1;

    .line 45
    .line 46
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    check-cast v0, Ljava/lang/Number;

    .line 51
    .line 52
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    float-to-int v0, v0

    .line 57
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    iget-object p0, p0, Lel/g;->f:Lay0/k;

    .line 62
    .line 63
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :pswitch_2
    sget-object v0, Lqg/c;->a:Lqg/c;

    .line 68
    .line 69
    iget-object v1, p0, Lel/g;->f:Lay0/k;

    .line 70
    .line 71
    invoke-interface {v1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 75
    .line 76
    iget-object p0, p0, Lel/g;->e:Ll2/b1;

    .line 77
    .line 78
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    goto :goto_0

    .line 82
    :pswitch_3
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 83
    .line 84
    iget-object v1, p0, Lel/g;->e:Ll2/b1;

    .line 85
    .line 86
    invoke-interface {v1, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    sget-object v0, Ldi/g;->a:Ldi/g;

    .line 90
    .line 91
    iget-object p0, p0, Lel/g;->f:Lay0/k;

    .line 92
    .line 93
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    goto :goto_0

    .line 97
    :pswitch_4
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 98
    .line 99
    iget-object v1, p0, Lel/g;->e:Ll2/b1;

    .line 100
    .line 101
    invoke-interface {v1, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    sget-object v0, Ldi/i;->a:Ldi/i;

    .line 105
    .line 106
    iget-object p0, p0, Lel/g;->f:Lay0/k;

    .line 107
    .line 108
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    goto :goto_0

    .line 112
    nop

    .line 113
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
